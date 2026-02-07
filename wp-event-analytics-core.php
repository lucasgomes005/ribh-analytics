<?php
/*
Plugin Name: RiBH Analytics
Description: Tracking resiliente de Views, Cliques em Ingressos e Compartilhamentos (anti-cache e anti-bloqueio).
Version: 1.0.27
Author: Core Analytics
*/

if (!defined('ABSPATH')) exit;

class WP_Event_Analytics_Core {

    const VERSION = '1.0.27';
    const TABLE_SUFFIX = 'event_analytics';
    const OPTION_DB_VERSION = 'wea_core_db_version';

    // Geo lookup (API externa) - deixe true se quiser cidade/estado automático
    const ENABLE_GEOLOOKUP = true;
    const GEO_ENDPOINT = 'https://ipapi.co/%s/json/';

    private static $schema_cols = null;

    public function __construct() {
        register_activation_hook(__FILE__, [$this, 'activate']);

        // Em updates, activation hook não roda => garantir upgrade de schema sempre
        add_action('plugins_loaded', [$this, 'maybe_upgrade_db'], 5);

        add_action('wp_footer', [$this, 'inject_tracking'], 20);

        add_action('wp_ajax_wea_track', [$this, 'ajax_track']);
        add_action('wp_ajax_nopriv_wea_track', [$this, 'ajax_track']);

        add_filter('script_loader_tag', [$this, 'disable_cf_async'], 10, 3);

        add_action('wp_dashboard_setup', [$this, 'register_dashboard_widget']);
        add_action('admin_menu', [$this, 'register_admin_pages']);
        add_action('admin_init', [$this, 'register_settings']);

        // Exportação (admin-post.php)
        add_action('admin_post_wea_export_csv', [$this, 'admin_export_csv']);
        add_action('admin_post_wea_export_pdf', [$this, 'admin_export_pdf']);
    }

    /* ========================
     * DB / Schema (com ALTER TABLE)
     * ======================== */
    private function table_name() {
        global $wpdb;
        return $wpdb->prefix . self::TABLE_SUFFIX;
    }

    public function activate() {
        $this->create_base_table();
        $this->ensure_schema_alter();
        $this->ensure_indexes();
        update_option(self::OPTION_DB_VERSION, self::VERSION, false);
        self::$schema_cols = null;
    }

    public function maybe_upgrade_db() {
        $this->create_base_table();
        $this->ensure_schema_alter();
        $this->ensure_indexes();
        $this->maybe_backfill_post_type();

        $db_version = get_option(self::OPTION_DB_VERSION, '');
        if ($db_version !== self::VERSION) {
            update_option(self::OPTION_DB_VERSION, self::VERSION, false);
            self::$schema_cols = null;
        }
    }

    private function create_base_table() {
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        global $wpdb;

        $table = $this->table_name();
        $charset = $wpdb->get_charset_collate();

        $sql = "
        CREATE TABLE IF NOT EXISTS $table (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            post_type VARCHAR(64) NULL,
            metric_type VARCHAR(50) NOT NULL,
            user_ip CHAR(64) NOT NULL,
            device_type VARCHAR(20) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_post_metric (post_id, metric_type),
            KEY idx_created_at (created_at),
            KEY idx_metric_type (metric_type),
            KEY idx_metric_created (metric_type, created_at)
        ) $charset;
        ";
        dbDelta($sql);
    }

    private function ensure_indexes() {
        global $wpdb;
        $table = $this->table_name();

        // Mapa: nome_do_indice => SQL para criar
        $wanted = [
            'idx_metric_type'    => "ALTER TABLE {$table} ADD INDEX idx_metric_type (metric_type)",
            'idx_metric_created' => "ALTER TABLE {$table} ADD INDEX idx_metric_created (metric_type, created_at)",
        ];

        $existing = [];
        $rows = $wpdb->get_results("SHOW INDEX FROM {$table}");
        if (is_array($rows)) {
            foreach ($rows as $r) {
                if (!empty($r->Key_name)) $existing[$r->Key_name] = true;
            }
        }

        foreach ($wanted as $name => $sql) {
            if (!isset($existing[$name])) {
                // Silencia erro para não derrubar site caso o host bloqueie ALTER
                $wpdb->query($sql);
            }
        }
    }

    private function get_schema_columns() {
        if (is_array(self::$schema_cols)) return self::$schema_cols;

        global $wpdb;
        $table = $this->table_name();
        $cols = [];

        $results = $wpdb->get_results("SHOW COLUMNS FROM {$table}");
        if (is_array($results)) {
            foreach ($results as $r) {
                if (!empty($r->Field)) $cols[$r->Field] = true;
            }
        }
        self::$schema_cols = $cols;
        return $cols;
    }

    private function has_col($name) {
        $cols = $this->get_schema_columns();
        return isset($cols[$name]);
    }

    private function ensure_schema_alter() {
        global $wpdb;
        $table = $this->table_name();

        $required = [
            'post_type'    => "VARCHAR(64) NULL",
            'user_ip_raw'  => "VARCHAR(45) NULL",
            'geo_city'     => "VARCHAR(120) NULL",
            'geo_region'   => "VARCHAR(120) NULL",
            'geo_country'  => "VARCHAR(8) NULL",
            'referrer_url' => "TEXT NULL",
            'landing_url'  => "TEXT NULL",
            'utm_source'   => "VARCHAR(255) NULL",
            'utm_medium'   => "VARCHAR(255) NULL",
            'utm_campaign' => "VARCHAR(255) NULL",
            'utm_content'  => "VARCHAR(255) NULL",
            'utm_term'     => "VARCHAR(255) NULL",
        ];

        self::$schema_cols = null;
        $cols = $this->get_schema_columns();

        foreach ($required as $col => $def) {
            if (!isset($cols[$col])) {
                // Silencia erro para não derrubar site caso o host bloqueie ALTER
                $wpdb->query("ALTER TABLE {$table} ADD COLUMN {$col} {$def}");
            }
        }

        self::$schema_cols = null;
    }

    /**
     * (v1.0.21) Backfill do post_type para registros antigos.
     * Roda uma vez (com flag em options) para evitar carga repetida.
     */
    private function maybe_backfill_post_type() {
        if (!$this->has_col('post_type')) return;

        $flag = 'wea_post_type_backfilled_1021';
        if (get_option($flag)) return;

        global $wpdb;
        $table = $this->table_name();
        $posts = $wpdb->posts;

        // Preenche post_type a partir da tabela wp_posts
        // Observação: JOIN garante que apenas IDs existentes serão preenchidos.
        $wpdb->query("UPDATE {$table} ea LEFT JOIN {$posts} p ON p.ID = ea.post_id SET ea.post_type = p.post_type WHERE (ea.post_type IS NULL OR ea.post_type = '') AND p.post_type IS NOT NULL");

        update_option($flag, 1, false);
        self::$schema_cols = null;
    }

    /* ========================
     * Scope
     * ======================== */
    private function is_valid_post_type() {
        if (!is_singular()) return false;

        return in_array(get_post_type(), [
            'agenda_do_rock',
            'agenda-do-rock',
            'calendario-motoclube',
            'calendario_motoclube'
        ], true);
    }

    /* ========================
     * Helpers (IP / Geo / Origin)
     * ======================== */
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            if (!empty($parts[0])) return sanitize_text_field(trim($parts[0]));
        }
        return sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    }

    private function sanitize_url_param($value) {
        if ($value === null) return null;
        $value = wp_unslash($value);
        $value = substr($value, 0, 2000);
        return esc_url_raw($value);
    }

    
private function respond_pixel() {
    header('Content-Type: image/gif');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
}

private function geo_lookup_cached($ip_raw, $ip_hash) {
        $data = ['city' => null, 'region' => null, 'country' => null];

        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $data['country'] = sanitize_text_field($_SERVER['HTTP_CF_IPCOUNTRY']);
        }

        if (!self::ENABLE_GEOLOOKUP) return $data;

        $key = 'wea_geo_' . substr($ip_hash, 0, 20);
        $cached = get_transient($key);
        if (is_array($cached)) return array_merge($data, $cached);

        if (in_array($ip_raw, ['127.0.0.1', '::1'], true)) {
            set_transient($key, $data, 30 * DAY_IN_SECONDS);
            return $data;
        }

        $url = sprintf(self::GEO_ENDPOINT, rawurlencode($ip_raw));
        $res = wp_remote_get($url, [
            'timeout' => 3,
            'headers' => ['User-Agent' => 'WP-Event-Analytics-Core/' . self::VERSION],
        ]);

        if (!is_wp_error($res)) {
            $code = (int) wp_remote_retrieve_response_code($res);
            $body = wp_remote_retrieve_body($res);
            if ($code >= 200 && $code < 300 && $body) {
                $json = json_decode($body, true);
                if (is_array($json)) {
                    $look = [
                        'city'    => !empty($json['city']) ? sanitize_text_field($json['city']) : null,
                        'region'  => !empty($json['region']) ? sanitize_text_field($json['region']) : null,
                        'country' => !empty($json['country']) ? sanitize_text_field($json['country']) : ($data['country'] ?? null),
                    ];
                    set_transient($key, $look, 30 * DAY_IN_SECONDS);
                    return array_merge($data, $look);
                }
            }
        }

        set_transient($key, $data, 7 * DAY_IN_SECONDS);
        return $data;
    }

    /* ========================
     * Frontend injection
     * ======================== */
    public function inject_tracking() {
        if (!$this->is_valid_post_type()) return;
        if ($this->get_opt_bool('wea_ignore_admins') && $this->is_admin_user()) return;

        global $post;
        $post_id = (int) $post->ID;
        $endpoint = esc_url(admin_url('admin-ajax.php'));

        $dl = rawurlencode(get_permalink($post_id));

        echo '<img src="' . $endpoint . '?action=wea_track&as_pixel=1&metric_type=view&post_id=' . $post_id . '&dl=' . $dl . '"
            width="1" height="1" style="display:none"
            data-cfasync="false" alt="" />';
        ?>
        <script data-cfasync="false">
        (function(){
            let lastFireTicket = 0;
            let lastFireShare = 0;
            const LOCK_MS = 1200;

            function validTicketTarget(el){
                const link = el.closest('a');
                if (!link) return false;
                if (link.closest('.botaoIngresso')) return true;
                const txt = (link.textContent || '').toLowerCase();
                return txt.includes('adquira') && txt.includes('ingresso');
            }

            function isWhatsappShareHref(href){
                if (!href) return false;
                href = href.toLowerCase();
                return (
                    href.includes('api.whatsapp.com/send') ||
                    href.includes('web.whatsapp.com/send') ||
                    href.includes('wa.me/') ||
                    href.startsWith('whatsapp://')
                );
            }

            function validWhatsappShareTarget(el){
                const link = el.closest('a');
                if (!link) return false;
                const href = (link.getAttribute('href') || '').toLowerCase();
                if (!isWhatsappShareHref(href)) return false;

                // Preferência: estrutura conhecida (.meta-share)
                if (link.closest('.meta-share')) return true;

                // Fallback: alguns temas mudam wrappers/classe, então aceita por texto
                const txt = (link.textContent || '').toLowerCase();
                if (txt.includes('whatsapp') || txt.includes('compartilh')) return true;

                return false;
            }

            function getUtmParams(){
                try{
                    const u = new URL(window.location.href);
                    const p = u.searchParams;
                    const keys = ['utm_source','utm_medium','utm_campaign','utm_content','utm_term'];
                    const out = {};
                    keys.forEach(k => {
                        const v = p.get(k);
                        if (v) out[k] = v;
                    });
                    return out;
                }catch(e){ return {}; }
            }

            function fire(metricType){
                const now = Date.now();
                if (metricType === 'click_ticket') {
                    if (now - lastFireTicket < LOCK_MS) return;
                    lastFireTicket = now;
                } else if (metricType === 'share_whatsapp') {
                    if (now - lastFireShare < LOCK_MS) return;
                    lastFireShare = now;
                }

                const dl = encodeURIComponent(window.location.href);
                const dr = encodeURIComponent(document.referrer || '');
                const utm = getUtmParams();

                let qs = "action=wea_track&as_pixel=1&metric_type=" + encodeURIComponent(metricType) + "&post_id=<?php echo (int)$post_id; ?>";
                qs += "&dl=" + dl + "&dr=" + dr;

                Object.keys(utm).forEach(k => {
                    qs += "&" + encodeURIComponent(k) + "=" + encodeURIComponent(utm[k]);
                });

                // Cache-buster para evitar qualquer interferência de cache/proxy
                qs += "&ts=" + now;

                const url = "<?php echo $endpoint; ?>?" + qs;

                // Em alguns celulares, abrir o WhatsApp pode pausar/encerrar o carregamento do pixel.
                // Por isso, tentamos fetch keepalive primeiro e caímos no pixel como fallback.
                try {
                    if (window.fetch) {
                        fetch(url, { method: 'GET', mode: 'no-cors', keepalive: true, credentials: 'omit' });
                    }
                } catch (e) {}

                const img = new Image();
                img.src = url;
            }

            ['pointerdown','touchstart','click'].forEach(evt => {
                document.addEventListener(evt, e => {
                    if (validTicketTarget(e.target)) {
                        fire('click_ticket');
                        return;
                    }
                    if (validWhatsappShareTarget(e.target)) {
                        fire('share_whatsapp');
                        return;
                    }
                }, true);
            });
        })();
        </script>
        <?php
    }

    /* ========================
     * Tracking endpoint
     * ======================== */
    public function ajax_track() {
        if ($this->get_opt_bool('wea_ignore_admins') && $this->is_admin_user()) {
            $this->respond_pixel();
            exit;
        }

        global $wpdb;
        $table = $this->table_name();

        // (v1.0.13) Validações básicas para evitar métricas inválidas e chamadas abusivas
        $post_id = isset($_GET['post_id']) ? absint($_GET['post_id']) : 0;
        $metric  = isset($_GET['metric_type']) ? sanitize_key($_GET['metric_type']) : '';

        // post_id precisa existir
        if (!$post_id || !get_post($post_id)) {
            status_header(400);
            exit;
        }

        // permitir apenas métricas conhecidas
        $allowed_metrics = array('view', 'click_ticket', 'share_whatsapp');
        if (!in_array($metric, $allowed_metrics, true)) {
            status_header(400);
            exit;
        }

        $ip_raw  = $this->get_client_ip();
        $ip_hash = hash('sha256', $ip_raw);
        $device  = wp_is_mobile() ? 'mobile' : 'desktop';

        // (v1.0.14) Rate limit leve por IP+post+métrica (evita spam e duplicações)
        $as_pixel = isset($_GET['as_pixel']);
        $ttl = ($metric === 'view') ? 60 : 10; // 60s para view, 10s para clique
        $rate_key = 'wea_rl_' . md5($metric . '|' . $post_id . '|' . $ip_hash);

        if (get_transient($rate_key)) {
            if ($as_pixel) {
                header('Content-Type: image/gif');
                header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
                header('Pragma: no-cache');
                echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
                exit;
            }
            wp_send_json_success(['rate_limited' => 1]);
        }

        set_transient($rate_key, 1, $ttl);


        $referrer = $this->sanitize_url_param($_GET['dr'] ?? ($_SERVER['HTTP_REFERER'] ?? null));
        $landing  = $this->sanitize_url_param($_GET['dl'] ?? null);

        $utm_source   = sanitize_text_field(wp_unslash($_GET['utm_source'] ?? ''));
        $utm_medium   = sanitize_text_field(wp_unslash($_GET['utm_medium'] ?? ''));
        $utm_campaign = sanitize_text_field(wp_unslash($_GET['utm_campaign'] ?? ''));
        $utm_content  = sanitize_text_field(wp_unslash($_GET['utm_content'] ?? ''));
        $utm_term     = sanitize_text_field(wp_unslash($_GET['utm_term'] ?? ''));

        $utm_source   = $utm_source !== '' ? substr($utm_source, 0, 255) : null;
        $utm_medium   = $utm_medium !== '' ? substr($utm_medium, 0, 255) : null;
        $utm_campaign = $utm_campaign !== '' ? substr($utm_campaign, 0, 255) : null;
        $utm_content  = $utm_content !== '' ? substr($utm_content, 0, 255) : null;
        $utm_term     = $utm_term !== '' ? substr($utm_term, 0, 255) : null;

        $geo = $this->geo_lookup_cached($ip_raw, $ip_hash);
        $geo_city    = $geo['city'] ? substr($geo['city'], 0, 120) : null;
        $geo_region  = $geo['region'] ? substr($geo['region'], 0, 120) : null;
        $geo_country = $geo['country'] ? substr($geo['country'], 0, 8) : null;

        // Se habilitado, registra SOMENTE visitantes do Brasil (BR)
// Se não for BR (ou se não for possível determinar), não grava o evento.
if ($this->get_opt_bool('wea_geo_only_br')) {
    $cc = strtoupper((string) $geo_country);
    if ($cc !== 'BR') {
        if ($as_pixel) {
            $this->respond_pixel();
            exit;
        }
        wp_send_json_success(['skipped_non_br' => 1]);
    }
}

$exists = $wpdb->get_var($wpdb->prepare("
            SELECT id FROM $table
            WHERE post_id = %d
              AND metric_type = %s
              AND user_ip = %s
              AND created_at >= (NOW() - INTERVAL 2 SECOND)
            LIMIT 1
        ", $post_id, $metric, $ip_hash));

        if (!$exists) {
            $post_type = get_post_type($post_id);
            $post_type = $post_type ? sanitize_key($post_type) : null;

            $data = [
                'post_id'     => $post_id,
                'metric_type' => $metric,
                'user_ip'     => $ip_hash,
                'device_type' => $device,
                'created_at'  => current_time('mysql'),
            ];

            if ($this->has_col('post_type'))    $data['post_type'] = $post_type;

            if ($this->has_col('user_ip_raw'))  $data['user_ip_raw'] = $ip_raw;

            if ($this->has_col('geo_city'))     $data['geo_city'] = $geo_city;
            if ($this->has_col('geo_region'))   $data['geo_region'] = $geo_region;
            if ($this->has_col('geo_country'))  $data['geo_country'] = $geo_country;

            if ($this->has_col('referrer_url')) $data['referrer_url'] = $referrer;
            if ($this->has_col('landing_url'))  $data['landing_url'] = $landing;

            if ($this->has_col('utm_source'))   $data['utm_source'] = $utm_source;
            if ($this->has_col('utm_medium'))   $data['utm_medium'] = $utm_medium;
            if ($this->has_col('utm_campaign')) $data['utm_campaign'] = $utm_campaign;
            if ($this->has_col('utm_content'))  $data['utm_content'] = $utm_content;
            if ($this->has_col('utm_term'))     $data['utm_term'] = $utm_term;

            $wpdb->insert($table, $data);
        }

        if (isset($_GET['as_pixel'])) {
            header('Content-Type: image/gif');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
            exit;
        }

        wp_send_json_success();
    }

    /* ========================
     * Export (CSV e PDF) - respeita filtros
     * ======================== */
    private function export_get_filters_from_request() {
        $metric = isset($_GET['metric_type']) ? sanitize_key($_GET['metric_type']) : '';
        $post_type = isset($_GET['wea_post_type']) ? sanitize_key($_GET['wea_post_type']) : '';
        $month  = isset($_GET['wea_month']) ? (int) $_GET['wea_month'] : 0;
        $year   = isset($_GET['wea_year']) ? (int) $_GET['wea_year'] : 0;
        $search = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';

        $orderby = isset($_GET['orderby']) ? sanitize_key($_GET['orderby']) : 'created_at';
        $order   = isset($_GET['order']) ? strtoupper(sanitize_key($_GET['order'])) : 'DESC';
        if (!in_array($order, ['ASC','DESC'], true)) $order = 'DESC';

        // Normaliza filtro de métrica (apenas as métricas existentes)
        if (!in_array($metric, ['','view','click_ticket','share_whatsapp'], true)) {
            $metric = '';
        }

        // Normaliza filtro de post_type (apenas os tipos rastreados pelo plugin)
        $allowed_pts = ['agenda_do_rock','agenda-do-rock','calendario-motoclube','calendario_motoclube'];
        if (!in_array($post_type, array_merge([''], $allowed_pts), true)) {
            $post_type = '';
        }

        if ($month < 1 || $month > 12) $month = 0;
        if ($year < 0) $year = 0;

        if (!in_array($orderby, ['created_at','post_title'], true)) {
            $orderby = 'created_at';
        }

        return [
            'metric'  => $metric,
            'post_type' => $post_type,
            'month'   => $month,
            'year'    => $year,
            'search'  => $search,
            'orderby' => $orderby,
            'order'   => $order,
        ];
    }

    private function export_build_where_and_params($filters) {
        global $wpdb;
        $where = '1=1';
        $params = [];

        if ($filters['metric'] !== '') { $where .= ' AND ea.metric_type = %s'; $params[] = $filters['metric']; }
        if (!empty($filters['post_type'])) {
            $where .= " AND COALESCE(NULLIF(ea.post_type, ''), p.post_type) = %s";
            $params[] = $filters['post_type'];
        }
        if ((int)$filters['year'] > 0) { $where .= ' AND YEAR(ea.created_at) = %d'; $params[] = (int)$filters['year']; }
        if ((int)$filters['month'] >= 1 && (int)$filters['month'] <= 12) { $where .= ' AND MONTH(ea.created_at) = %d'; $params[] = (int)$filters['month']; }

        if ($filters['search'] !== '') {
            $search = $filters['search'];
            if (ctype_digit($search)) {
                $where .= ' AND (ea.post_id = %d OR p.post_title LIKE %s)';
                $params[] = (int)$search;
                $params[] = '%' . $wpdb->esc_like($search) . '%';
            } else {
                $where .= ' AND p.post_title LIKE %s';
                $params[] = '%' . $wpdb->esc_like($search) . '%';
            }
        }

        return [$where, $params];
    }

    private function export_get_orderby_sql($filters) {
        return ($filters['orderby'] === 'post_title') ? 'p.post_title' : 'ea.created_at';
    }

    private function export_get_select_sql($table) {
        // Sempre existem:
        $select_parts = [
            'ea.post_id',
            'p.post_title',
            ($this->has_col('post_type') ? 'ea.post_type AS post_type' : 'p.post_type AS post_type'),
            'ea.metric_type',
            'ea.device_type',
            'ea.created_at',
            'ea.user_ip AS ip_hash',
        ];

        // Opcionais (podem não existir dependendo do schema)
        $optional = [
            'user_ip_raw',
            'geo_city',
            'geo_region',
            'geo_country',
            'referrer_url',
            'landing_url',
            'utm_source',
            'utm_medium',
            'utm_campaign',
            'utm_content',
            'utm_term',
        ];

        foreach ($optional as $col) {
            if ($this->has_col($col)) {
                $select_parts[] = 'ea.' . $col;
            } else {
                $select_parts[] = 'NULL AS ' . $col;
            }
        }

        return implode(",\n                       ", $select_parts);
    }

    private function export_filters_summary_line($filters) {
        $parts = [];
        if ($filters['metric'] !== '') $parts[] = 'metric=' . $filters['metric'];
        if (!empty($filters['post_type'])) $parts[] = 'post_type=' . $filters['post_type'];
        if ((int)$filters['month'] > 0) $parts[] = 'month=' . sprintf('%02d', (int)$filters['month']);
        if ((int)$filters['year'] > 0)  $parts[] = 'year=' . (int)$filters['year'];
        if ($filters['search'] !== '') $parts[] = 'search=' . $filters['search'];
        $parts[] = 'orderby=' . $filters['orderby'];
        $parts[] = 'order=' . $filters['order'];
        return implode('; ', $parts);
    }

    public function admin_export_csv() {
        if (!current_user_can('manage_options')) wp_die('Sem permissão.');
        check_admin_referer('wea_export');

        global $wpdb;
        $table = $this->table_name();
        $posts = $wpdb->posts;

        $filters = $this->export_get_filters_from_request();
        list($where, $params) = $this->export_build_where_and_params($filters);
        $orderby_sql = $this->export_get_orderby_sql($filters);
        $order = $filters['order'];

        $select_sql = $this->export_get_select_sql($table);

        $filename = 'wea_historico_' . current_time('Ymd_His') . '.csv';
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename=' . $filename);
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');

        // BOM para Excel/Google Sheets interpretar UTF-8 corretamente
        echo "\xEF\xBB\xBF";

        $out = fopen('php://output', 'w');

        // Linha de contexto (útil para IA)
        fputcsv($out, ['exported_at', current_time('Y-m-d H:i:s'), 'filters', $this->export_filters_summary_line($filters)]);
        fputcsv($out, []);

        $header = [
            'post_id',
            'post_title',
            'post_type',
            'metric_type',
            'device_type',
            'created_at',
            'user_ip_raw',
            'geo_city',
            'geo_region',
            'geo_country',
            'referrer_url',
            'landing_url',
            'utm_source',
            'utm_medium',
            'utm_campaign',
            'utm_content',
            'utm_term',
            'ip_hash',
        ];
        fputcsv($out, $header);

        $limit = 1000;
        $offset = 0;
        $max_rows = 20000; // limite de segurança (CSV continua bom p/ IA e evita travar admin)
        $sent = 0;

        while (true) {
            $sql = "
                SELECT {$select_sql}
                FROM {$table} ea
                LEFT JOIN {$posts} p ON p.ID = ea.post_id
                WHERE {$where}
                ORDER BY {$orderby_sql} {$order}
                LIMIT %d OFFSET %d
            ";
            $batch_params = array_merge($params, [$limit, $offset]);
            $rows = $wpdb->get_results($wpdb->prepare($sql, $batch_params));
            if (!$rows) break;

            foreach ($rows as $r) {
                fputcsv($out, [
                    (int)$r->post_id,
                    (string)($r->post_title ?? ''),
                    (string)($r->post_type ?? ''),
                    (string)($r->metric_type ?? ''),
                    (string)($r->device_type ?? ''),
                    (string)($r->created_at ?? ''),
                    (string)($r->user_ip_raw ?? ''),
                    (string)($r->geo_city ?? ''),
                    (string)($r->geo_region ?? ''),
                    (string)($r->geo_country ?? ''),
                    (string)($r->referrer_url ?? ''),
                    (string)($r->landing_url ?? ''),
                    (string)($r->utm_source ?? ''),
                    (string)($r->utm_medium ?? ''),
                    (string)($r->utm_campaign ?? ''),
                    (string)($r->utm_content ?? ''),
                    (string)($r->utm_term ?? ''),
                    (string)($r->ip_hash ?? ''),
                ]);
                $sent++;
                if ($sent >= $max_rows) {
                    fputcsv($out, ['NOTICE', 'export_truncated', 'max_rows_reached', $max_rows]);
                    fclose($out);
                    exit;
                }
            }

            $offset += $limit;
        }

        fclose($out);
        exit;
    }

    private function pdf_escape_text($text) {
        $text = (string) $text;
        $text = str_replace('\\', '\\\\', $text);
        $text = str_replace('(', '\\(', $text);
        $text = str_replace(')', '\\)', $text);
        // remove quebras para não quebrar o content stream
        $text = str_replace(["\r", "\n"], [' ', ' '], $text);
        return $text;
    }

    private function build_simple_pdf($title, $lines, $meta = []) {
        // Gera um PDF minimalista com múltiplas páginas (texto monoespaçado não, mas legível)
        $page_w = 612; // 8.5in * 72
        $page_h = 792; // 11in * 72
        $margin_left = 36;
        $margin_top = 40;
        $line_h = 12;
        $font_size = 9;
        $max_lines_per_page = (int)(($page_h - ($margin_top * 2)) / $line_h);
        if ($max_lines_per_page < 30) $max_lines_per_page = 30;

        $chunks = array_chunk($lines, $max_lines_per_page);
        if (empty($chunks)) $chunks = [[]];

        $objects = [];
        $offsets = [];

        $add_obj = function($content) use (&$objects) {
            $objects[] = $content;
            return count($objects);
        };

        // 1) Catalog e Pages serão definidos depois
        $catalog_id = $add_obj('');
        $pages_id   = $add_obj('');

        // 3) Fonte
        $font_id = $add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

        $page_ids = [];
        $content_ids = [];

        foreach ($chunks as $page_index => $page_lines) {
            $y = $page_h - $margin_top;
            $stream = "BT\n/F1 {$font_size} Tf\n";

            // Título no topo (primeira página)
            if ($page_index === 0) {
                $t = $this->pdf_escape_text($title);
                $stream .= sprintf("%d %d Td (%s) Tj\n", $margin_left, $y, $t);
                $y -= ($line_h * 2);

                if (!empty($meta)) {
                    foreach ($meta as $m) {
                        $m = $this->pdf_escape_text($m);
                        $stream .= sprintf("0 -%d Td (%s) Tj\n", $line_h, $m);
                        $y -= $line_h;
                    }
                    $y -= $line_h;
                    $stream .= sprintf("0 -%d Td ( ) Tj\n", $line_h);
                    $y -= $line_h;
                } else {
                    $stream .= sprintf("0 -%d Td ( ) Tj\n", $line_h);
                    $y -= $line_h;
                }
            } else {
                // move cursor para topo
                $stream .= sprintf("%d %d Td\n", $margin_left, $y);
            }

            $first_line = true;
            foreach ($page_lines as $ln) {
                $ln = $this->pdf_escape_text($ln);
                if ($first_line && $page_index !== 0) {
                    $stream .= "({$ln}) Tj\n";
                    $first_line = false;
                } else {
                    $stream .= sprintf("0 -%d Td (%s) Tj\n", $line_h, $ln);
                }
            }
            $stream .= "ET\n";

            $len = strlen($stream);
            $content_obj = "<< /Length {$len} >>\nstream\n{$stream}endstream";
            $content_id = $add_obj($content_obj);
            $content_ids[] = $content_id;

            $page_obj = "<< /Type /Page /Parent {$pages_id} 0 R /MediaBox [0 0 {$page_w} {$page_h}] /Resources << /Font << /F1 {$font_id} 0 R >> >> /Contents {$content_id} 0 R >>";
            $page_id = $add_obj($page_obj);
            $page_ids[] = $page_id;
        }

        // Pages
        $kids = implode(' ', array_map(function($id){ return $id . ' 0 R'; }, $page_ids));
        $objects[$pages_id - 1] = "<< /Type /Pages /Kids [ {$kids} ] /Count " . count($page_ids) . " >>";

        // Catalog
        $objects[$catalog_id - 1] = "<< /Type /Catalog /Pages {$pages_id} 0 R >>";

        // Monta arquivo com offsets
        $pdf = "%PDF-1.3\n";
        $offsets[] = 0;
        foreach ($objects as $i => $obj) {
            $offsets[] = strlen($pdf);
            $id = $i + 1;
            $pdf .= "{$id} 0 obj\n{$obj}\nendobj\n";
        }

        $xref_pos = strlen($pdf);
        $pdf .= "xref\n0 " . (count($objects) + 1) . "\n";
        $pdf .= "0000000000 65535 f \n";
        for ($i = 1; $i <= count($objects); $i++) {
            $pdf .= sprintf("%010d 00000 n \n", $offsets[$i]);
        }
        $pdf .= "trailer\n<< /Size " . (count($objects) + 1) . " /Root {$catalog_id} 0 R >>\n";
        $pdf .= "startxref\n{$xref_pos}\n%%EOF";

        return $pdf;
    }

    public function admin_export_pdf() {
        if (!current_user_can('manage_options')) wp_die('Sem permissão.');
        check_admin_referer('wea_export');

        global $wpdb;
        $table = $this->table_name();
        $posts = $wpdb->posts;

        $filters = $this->export_get_filters_from_request();
        list($where, $params) = $this->export_build_where_and_params($filters);
        $orderby_sql = $this->export_get_orderby_sql($filters);
        $order = $filters['order'];

        $select_sql = $this->export_get_select_sql($table);

        // Para PDF, colocamos um limite menor para não gerar um arquivo gigantesco
        $limit = 1000;
        $offset = 0;
        $max_rows = 3000;
        $sent = 0;

        $lines = [];
        $lines[] = 'post_id | post_title | post_type | metric_type | device | created_at | ip | geo | origin | landing | utm';
        $lines[] = str_repeat('-', 120);

        while (true) {
            $sql = "
                SELECT {$select_sql}
                FROM {$table} ea
                LEFT JOIN {$posts} p ON p.ID = ea.post_id
                WHERE {$where}
                ORDER BY {$orderby_sql} {$order}
                LIMIT %d OFFSET %d
            ";
            $batch_params = array_merge($params, [$limit, $offset]);
            $rows = $wpdb->get_results($wpdb->prepare($sql, $batch_params));
            if (!$rows) break;

            foreach ($rows as $r) {
                $geo = trim((string)($r->geo_city ?? ''));
                $reg = trim((string)($r->geo_region ?? ''));
                $cty = trim((string)($r->geo_country ?? ''));
                $geo_label = trim($geo . ($geo && $reg ? '/' : '') . $reg);
                if ($cty) $geo_label = trim($geo_label . ($geo_label ? ' - ' : '') . $cty);

                $origin = '';
                $utm_parts = [];
                if (!empty($r->utm_source))   $utm_parts[] = 'src=' . $r->utm_source;
                if (!empty($r->utm_medium))   $utm_parts[] = 'med=' . $r->utm_medium;
                if (!empty($r->utm_campaign)) $utm_parts[] = 'camp=' . $r->utm_campaign;
                if (!empty($r->utm_content))  $utm_parts[] = 'cont=' . $r->utm_content;
                if (!empty($r->utm_term))     $utm_parts[] = 'term=' . $r->utm_term;
                $utm_label = implode('&', $utm_parts);

                if ($utm_label !== '') {
                    $origin = $utm_label;
                } else if (!empty($r->referrer_url)) {
                    $host = wp_parse_url($r->referrer_url, PHP_URL_HOST);
                    $origin = $host ? $host : $r->referrer_url;
                } else {
                    $origin = 'direto/unknown';
                }

                $ip = !empty($r->user_ip_raw) ? $r->user_ip_raw : $r->ip_hash;
                $line = sprintf(
                    "%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s",
                    (int)$r->post_id,
                    (string)($r->post_title ?? ''),
                    (string)($r->post_type ?? ''),
                    (string)($r->metric_type ?? ''),
                    (string)($r->device_type ?? ''),
                    (string)($r->created_at ?? ''),
                    (string)$ip,
                    (string)($geo_label ?: '—'),
                    (string)$origin,
                    (string)($r->landing_url ?? ''),
                    (string)$utm_label
                );
                // Evita linhas absurdamente longas
                if (strlen($line) > 500) $line = substr($line, 0, 497) . '...';
                $lines[] = $line;

                $sent++;
                if ($sent >= $max_rows) {
                    $lines[] = 'NOTICE | export_truncated | max_rows_reached=' . $max_rows;
                    break 2;
                }
            }

            $offset += $limit;
        }

        $meta = [
            'exported_at: ' . current_time('Y-m-d H:i:s'),
            'filters: ' . $this->export_filters_summary_line($filters),
            'rows: ' . $sent,
        ];

        $pdf = $this->build_simple_pdf('RiBH Analytics - Relatório', $lines, $meta);

        $filename = 'wea_historico_' . current_time('Ymd_His') . '.pdf';
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename=' . $filename);
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        echo $pdf;
        exit;
    }

    /* ========================
     * Admin UI
     * ======================== */
    public function register_admin_pages() {
        add_menu_page(
            'RiBH Analytics',
            'RiBH Analytics',
            'manage_options',
            'wea-history',
            [$this, 'render_history_page'],
            'dashicons-chart-bar'
        );

        add_submenu_page(
            'wea-history',
            'Configurações',
            'Configurações',
            'manage_options',
            'wea-settings',
            [$this, 'render_settings_page']
        );
    }

    

    /* ========================
     * Settings
     * ======================== */
    public function register_settings() {
        register_setting('wea_settings_group', 'wea_ignore_admins', [
            'type' => 'boolean',
            'sanitize_callback' => function($value) { return !empty($value) ? 1 : 0; },
            'default' => 0,
        ]);

        register_setting('wea_settings_group', 'wea_geo_only_br', [
            'type' => 'boolean',
            'sanitize_callback' => function($value) { return !empty($value) ? 1 : 0; },
            'default' => 0,
        ]);

        add_settings_section(
            'wea_settings_main',
            'Preferências de Coleta',
            function() {
                echo '<p>Configure o que deve ou não ser registrado pelo plugin.</p>';
            },
            'wea-settings'
        );

        add_settings_field(
            'wea_ignore_admins',
            'Ignorar Administradores',
            [$this, 'field_ignore_admins'],
            'wea-settings',
            'wea_settings_main'
        );

        add_settings_field(
            'wea_geo_only_br',
            'Não registrar localidade fora do Brasil (BR)',
            [$this, 'field_geo_only_br'],
            'wea-settings',
            'wea_settings_main'
        );
    }

    private function is_admin_user() {
        return is_user_logged_in() && current_user_can('manage_options');
    }

    private function get_opt_bool($key, $default = 0) {
        $val = get_option($key, $default);
        return !empty($val);
    }

    public function field_ignore_admins() {
        $checked = $this->get_opt_bool('wea_ignore_admins') ? 'checked' : '';
        echo '<label><input type="checkbox" name="wea_ignore_admins" value="1" ' . $checked . '> Não registrar eventos gerados por usuários administradores.</label>';
    }

    public function field_geo_only_br() {
        $checked = $this->get_opt_bool('wea_geo_only_br') ? 'checked' : '';
        echo '<label><input type="checkbox" name="wea_geo_only_br" value="1" ' . $checked . '> Registrar atividades somente quando o visitante estiver no Brasil (BR).</label>';
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) wp_die('Sem permissão.');
        echo '<div class="wrap">';
        echo '<h1>Configurações</h1>';
        echo '<form method="post" action="options.php">';
        settings_fields('wea_settings_group');
        do_settings_sections('wea-settings');
        submit_button('Salvar Alterações');
        echo '</form>';
        echo '</div>';
    }

public function render_history_page() {
        if (!current_user_can('manage_options')) wp_die('Sem permissão.');

        if (!class_exists('WP_List_Table')) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
        }
        if (!class_exists('WEA_Events_List_Table')) {
            echo '<div class="wrap"><h1>Histórico de Eventos</h1><p>Erro: List Table não carregou.</p></div>';
            return;
        }

        $table = new WEA_Events_List_Table();
        $table->prepare_items();

        echo '<div class="wrap">';
        echo '<h1>Histórico de Eventos</h1>';
        echo '<p><strong>Total de registros:</strong> ' . number_format_i18n($table->get_total_items()) . '</p>';
        echo '<form method="get">';
        echo '<input type="hidden" name="page" value="wea-history" />';
        $table->search_box('Buscar Evento (título ou ID)', 'wea_search_id');
        $table->display();
        echo '</form>';
        echo '</div>';
    }

    public function register_dashboard_widget() {
        // Widget principal (contadores + últimos registros)
        wp_add_dashboard_widget('wea_dashboard', 'RiBH Analytics', [$this, 'dashboard_render']);

        // Widget: rankings TOP 5 por métrica (período selecionável)
        wp_add_dashboard_widget('wea_dashboard_rankings', 'RiBH Analytics: Top 5 por Ação', [$this, 'dashboard_rankings_render']);
    }

    public function dashboard_render() {
        global $wpdb;
        $table = $this->table_name();
        $posts = $wpdb->posts;

        $views  = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE metric_type='view'");
        $clicks = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE metric_type='click_ticket'");
        $shares = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE metric_type='share_whatsapp'");
        echo "<p><strong>Views:</strong> " . number_format_i18n($views) . "</p>";
        echo "<p><strong>Cliques em Ingresso:</strong> " . number_format_i18n($clicks) . "</p>";
        echo "<p><strong>Compartilhamentos (WhatsApp):</strong> " . number_format_i18n($shares) . "</p>";
        echo '<p><a href="' . esc_url(admin_url('admin.php?page=wea-history')) . '">Ver histórico completo</a></p>';

        $rows = $wpdb->get_results($wpdb->prepare("
            SELECT ea.post_id, ea.metric_type, ea.device_type, ea.created_at, p.post_title
            FROM {$table} ea
            LEFT JOIN {$posts} p ON p.ID = ea.post_id
            ORDER BY ea.created_at DESC
            LIMIT %d
        ", 15));

        echo "<table class='widefat striped' style='margin-top:10px'><thead>
            <tr><th>Evento</th><th>Métrica</th><th>Device</th><th>Data</th></tr>
        </thead><tbody>";

        if (!$rows) {
            echo "<tr><td colspan='4'>Nenhum registro ainda.</td></tr>";
        } else {
            foreach ($rows as $r) {
                $title = $r->post_title ? $r->post_title : '(sem título)';
                $label = esc_html($title) . ' (#' . (int)$r->post_id . ')';
                $edit = get_edit_post_link((int)$r->post_id);
                $event_cell = $edit ? '<a href="' . esc_url($edit) . '">' . $label . '</a>' : $label;

                echo "<tr>
                    <td>{$event_cell}</td>
                    <td>" . esc_html($r->metric_type) . "</td>
                    <td>" . esc_html($r->device_type) . "</td>
                    <td>" . esc_html(mysql2date('d/m/Y H:i:s', $r->created_at)) . "</td>
                </tr>";
            }
        }

        echo "</tbody></table>";
    }

    /**
     * Novo widget: TOP 5 por métrica nos últimos 7 dias.
     * Renderiza um gráfico em barras (HTML/CSS) com quantidade.
     */
    public function dashboard_rankings_render() {
        global $wpdb;
        $table = $this->table_name();
        $posts = $wpdb->posts;

        // Período (dias) selecionável no próprio widget: 7/14/30
        $days_allowed = [7, 14, 30];
        $days = isset($_GET['ribh_days']) ? (int) $_GET['ribh_days'] : 7;
        if (!in_array($days, $days_allowed, true)) {
            $days = 7;
        }
        // Inclui "agora"
        $since = gmdate('Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS);

        // Busca agregada (top 5 por métrica)
        // Observação: wpdb->prepare com %s para data.
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "
                SELECT ea.metric_type, ea.post_id, COUNT(*) AS qty, COALESCE(p.post_title, '') AS post_title
                FROM {$table} ea
                LEFT JOIN {$posts} p ON p.ID = ea.post_id
                WHERE ea.created_at >= %s
                  AND ea.metric_type IN ('view','click_ticket','share_whatsapp')
                GROUP BY ea.metric_type, ea.post_id
                ORDER BY ea.metric_type ASC, qty DESC
                ",
                $since
            ),
            ARRAY_A
        );

        $metrics = [
            'view' => '👀 Visitas',
            'click_ticket' => '🎟️ Cliques em ingressos',
            'share_whatsapp' => '📲 Compartilhamentos (WhatsApp)',
        ];

        // Mapa de views por post_id (para calcular taxas de clique/compartilhamento)
        $views_map = [];
        $view_rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT post_id, COUNT(*) AS qty FROM {$table} WHERE created_at >= %s AND metric_type='view' GROUP BY post_id",
                $since
            ),
            ARRAY_A
        );
        if (is_array($view_rows)) {
            foreach ($view_rows as $vr) {
                $pid = (int)($vr['post_id'] ?? 0);
                if ($pid > 0) {
                    $views_map[$pid] = (int)($vr['qty'] ?? 0);
                }
            }
        }

        // Organiza e limita TOP 5 por métrica
        $top = [ 'view' => [], 'click_ticket' => [], 'share_whatsapp' => [] ];
        if (is_array($rows)) {
            foreach ($rows as $r) {
                $m = $r['metric_type'] ?? '';
                if (!isset($top[$m])) continue;
                if (count($top[$m]) >= 5) continue;
                $top[$m][] = $r;
            }
        }

        // Estilos simples para o gráfico em barras
        echo '<style>
            .ribh-wrap{display:flex;flex-direction:column;gap:12px;}
            .ribh-card{border:1px solid #dcdcde;border-radius:8px;padding:10px;background:#fff;}
            .ribh-title{margin:0 0 8px;font-size:13px;}
            .ribh-row{display:grid;grid-template-columns:1fr 54px;gap:8px;align-items:center;margin:8px 0;}
            .ribh-label{font-size:12px;line-height:1.25;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}
            .ribh-bar-outer{height:10px;background:#f0f0f1;border-radius:999px;overflow:hidden;margin-top:4px;}
            .ribh-bar-inner{height:10px;background:#2271b1;border-radius:999px;}
            .ribh-qty{font-variant-numeric:tabular-nums;text-align:right;font-weight:600;}
            .ribh-rate{display:block;margin-top:2px;color:#646970;font-weight:400;font-size:11px;}
            .ribh-controls{display:flex;gap:8px;align-items:center;margin:0 0 10px;}
            .ribh-controls label{font-size:12px;color:#1d2327;}
            .ribh-controls select{font-size:12px;}
            .ribh-note{margin:10px 0 0;color:#646970;font-size:12px;}
        </style>';

        // Controles do widget (período)
        echo '<form class="ribh-controls" method="get">';
        // no Dashboard (index.php), basta reenviar ribh_days
        echo '<label for="ribh_days"><strong>Período:</strong></label>';
        echo '<select id="ribh_days" name="ribh_days">';
        foreach ($days_allowed as $d) {
            echo '<option value="' . (int)$d . '"' . selected($days, $d, false) . '>Últimos ' . (int)$d . ' dias</option>';
        }
        echo '</select>';
        echo '<button class="button" type="submit">Aplicar</button>';
        echo '</form>';

        echo '<div class="ribh-wrap">';

        foreach ($metrics as $metric => $label) {
            $items = $top[$metric] ?? [];
            $max = 0;
            foreach ($items as $it) {
                $q = (int)($it['qty'] ?? 0);
                if ($q > $max) $max = $q;
            }

            echo '<div class="ribh-card">';
            echo '<p class="ribh-title"><strong>' . esc_html($label) . '</strong> <span style="font-weight:400;color:#646970">(TOP 5)</span></p>';

            if (!$items) {
                echo '<p style="margin:0;color:#646970;font-size:12px;">Nenhum registro nos últimos ' . (int)$days . ' dias.</p>';
            } else {
                foreach ($items as $it) {
                    $post_id = (int)($it['post_id'] ?? 0);
                    $title = trim((string)($it['post_title'] ?? ''));
                    if ($title === '') $title = '(sem título)';
                    $qty = (int)($it['qty'] ?? 0);
                    $pct = ($max > 0) ? round(($qty / $max) * 100) : 0;

                    $edit = $post_id ? get_edit_post_link($post_id) : '';
                    $label_html = esc_html($title) . ' <span style="color:#646970">(#' . $post_id . ')</span>';
                    if ($edit) {
                        $label_html = '<a href="' . esc_url($edit) . '">' . $label_html . '</a>';
                    }

                    // Taxas (apenas para cliques/compartilhamentos)
                    $rate_html = '';
                    if ($metric !== 'view') {
                        $views = (int)($views_map[$post_id] ?? 0);
                        if ($views > 0) {
                            $rate = ($qty / $views) * 100;
                            $rate_html = '<span class="ribh-rate">' . esc_html(number_format_i18n($rate, 1)) . '% por view</span>';
                        } else {
                            $rate_html = '<span class="ribh-rate">sem views no período</span>';
                        }
                    }

                    echo '<div class="ribh-row">';
                    echo '<div>';
                    echo '<div class="ribh-label">' . $label_html . '</div>';
                    echo '<div class="ribh-bar-outer"><div class="ribh-bar-inner" style="width:' . (int)$pct . '%"></div></div>';
                    echo '</div>';
                    echo '<div class="ribh-qty">' . number_format_i18n($qty) . $rate_html . '</div>';
                    echo '</div>';
                }
            }

            echo '</div>';
        }

        echo '</div>';
        echo '<p class="ribh-note">Período considerado: últimos ' . (int)$days . ' dias (a partir de ' . esc_html(mysql2date('d/m/Y H:i', $since)) . ').</p>';
    }

    /* ========================
     * Cloudflare safety
     * ======================== */
    public function disable_cf_async($tag, $handle, $src) {
        if (strpos($src, 'wea-core.js') !== false) {
            return str_replace('<script ', '<script data-cfasync="false" ', $tag);
        }
        return $tag;
    }
}

/**
 * Admin-only List Table com colunas novas: IP, Localidade, Origem
 */
if (is_admin()) {
    if (!class_exists('WP_List_Table')) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
    }

    class WEA_Events_List_Table extends WP_List_Table {
        private $total_items = 0;

        // Cache local do schema para evitar queries repetidas (e evitar "Histórico vazio" se faltar coluna).
        private static $schema_cols_cache = [];

        private function get_table_columns_cached($table) {
            global $wpdb;
            if (isset(self::$schema_cols_cache[$table])) {
                return self::$schema_cols_cache[$table];
            }
            $cols = [];
            // Protege contra erro: se SHOW COLUMNS falhar, retorna vazio e a query usa NULL AS coluna.
            $safe_table = str_replace('`', '', $table);
            $rows = $wpdb->get_results("SHOW COLUMNS FROM `{$safe_table}`", ARRAY_A);
            if (is_array($rows)) {
                foreach ($rows as $r) {
                    if (!empty($r['Field'])) $cols[strtolower($r['Field'])] = true;
                }
            }
            self::$schema_cols_cache[$table] = $cols;
            return $cols;
        }

        private function table_has_column($table, $col) {
            $cols = $this->get_table_columns_cached($table);
            return isset($cols[strtolower($col)]);
        }

        public function get_columns() {
            return [
                'post'   => 'Evento',
                'post_type' => 'Post Type',
                'metric' => 'Métrica',
                'device' => 'Device',
                'geo'    => 'Localidade',
                'origin' => 'Origem',
                'ip'     => 'IP',
                'date'   => 'Data',
            ];
        }

        public function get_sortable_columns() {
            return [
                'date' => ['created_at', true],
                'post' => ['post_title', false],
            ];
        }

        private function get_request_int($key, $default = 0) {
            return isset($_GET[$key]) ? (int) $_GET[$key] : $default;
        }

        private function get_request_str($key, $default = '') {
            return isset($_GET[$key]) ? sanitize_text_field(wp_unslash($_GET[$key])) : $default;
        }

        public function extra_tablenav($which) {
            if ($which !== 'top') return;

            $month = $this->get_request_int('wea_month', 0);
            $year  = $this->get_request_int('wea_year', 0);
            $metric = $this->get_request_str('metric_type', '');
            $post_type = sanitize_key($this->get_request_str('wea_post_type', ''));
            $per_page = $this->get_request_int('wea_per_page', 50);

            echo '<div class="alignleft actions">';

            echo '<select name="metric_type">';
            echo '<option value="">Todas as métricas</option>';
            echo '<option value="view"' . selected($metric, 'view', false) . '>view</option>';
            echo '<option value="click_ticket"' . selected($metric, 'click_ticket', false) . '>click_ticket</option>';
            echo '<option value=\"share_whatsapp\"' . selected($metric, 'share_whatsapp', false) . '>share_whatsapp</option>';
            echo '</select>';

            // Filtro por post_type
            $allowed_pts = [
                'agenda_do_rock' => 'agenda_do_rock',
                'agenda-do-rock' => 'agenda-do-rock',
                'calendario-motoclube' => 'calendario-motoclube',
                'calendario_motoclube' => 'calendario_motoclube',
            ];
            echo '<select name="wea_post_type">';
            echo '<option value="">Todos os post_types</option>';
            foreach ($allowed_pts as $k => $label) {
                echo '<option value="' . esc_attr($k) . '"' . selected($post_type, $k, false) . '>' . esc_html($label) . '</option>';
            }
            echo '</select>';

            echo '<select name="wea_month">';
            echo '<option value="0">Todos os meses</option>';
            for ($m = 1; $m <= 12; $m++) {
                echo '<option value="' . esc_attr($m) . '"' . selected($month, $m, false) . '>' . esc_html(sprintf('%02d', $m)) . '</option>';
            }
            echo '</select>';

            $current_year = (int) current_time('Y');
            echo '<select name="wea_year">';
            echo '<option value="0">Todos os anos</option>';
            for ($y = $current_year; $y >= $current_year - 6; $y--) {
                echo '<option value="' . esc_attr($y) . '"' . selected($year, $y, false) . '>' . esc_html($y) . '</option>';
            }
            echo '</select>';

            $opts = [20, 50, 100, 200];
            echo '<select name="wea_per_page">';
            foreach ($opts as $opt) {
                echo '<option value="' . esc_attr($opt) . '"' . selected($per_page, $opt, false) . '>' . esc_html($opt) . ' / página</option>';
            }
            echo '</select>';

            submit_button('Filtrar', '', 'filter_action', false);
            $reset_url = admin_url('admin.php?page=wea-history');
            echo ' <a href="' . esc_url($reset_url) . '" class="button">Limpar Filtro</a>';

            // Exportar (CSV/PDF) respeitando os filtros atuais
            $nonce = wp_create_nonce('wea_export');
            $base = admin_url('admin-post.php');
            $search = $this->get_request_str('s', '');
            $orderby = $this->get_request_str('orderby', 'created_at');
            $order = $this->get_request_str('order', 'DESC');

            $common_args = [
                '_wpnonce'   => $nonce,
                'metric_type'=> $metric,
                'wea_post_type' => $post_type,
                'wea_month'  => $month,
                'wea_year'   => $year,
                's'          => $search,
                'orderby'    => $orderby,
                'order'      => $order,
            ];

            $csv_url = add_query_arg(array_merge(['action' => 'wea_export_csv'], $common_args), $base);
            $pdf_url = add_query_arg(array_merge(['action' => 'wea_export_pdf'], $common_args), $base);

            echo ' <a href="' . esc_url($csv_url) . '" class="button">Exportar CSV</a>';
            echo ' <a href="' . esc_url($pdf_url) . '" class="button">Exportar PDF</a>';
            echo '</div>';
        }

        private function origin_label($item) {
            $parts = [];
            if (!empty($item->utm_source))   $parts[] = 'src: ' . $item->utm_source;
            if (!empty($item->utm_medium))   $parts[] = 'med: ' . $item->utm_medium;
            if (!empty($item->utm_campaign)) $parts[] = 'camp: ' . $item->utm_campaign;
            if ($parts) return esc_html(implode(' | ', $parts));

            if (!empty($item->referrer_url)) {
                $host = wp_parse_url($item->referrer_url, PHP_URL_HOST);
                return esc_html($host ? $host : $item->referrer_url);
            }

            return 'direto/unknown';
        }

        public function prepare_items() {
            global $wpdb;

            $table = $wpdb->prefix . WP_Event_Analytics_Core::TABLE_SUFFIX;
            $posts = $wpdb->posts;

            $per_page = $this->get_request_int('wea_per_page', 50);
            if (!in_array($per_page, [20,50,100,200], true)) $per_page = 50;

            $paged  = max(1, $this->get_request_int('paged', 1));
            $offset = ($paged - 1) * $per_page;

            $metric = $this->get_request_str('metric_type', '');
            $post_type = sanitize_key($this->get_request_str('wea_post_type', ''));
            $month  = $this->get_request_int('wea_month', 0);
            $year   = $this->get_request_int('wea_year', 0);
            $search = $this->get_request_str('s', '');

            $orderby = $this->get_request_str('orderby', 'created_at');
            $order   = strtoupper($this->get_request_str('order', 'DESC'));
            if (!in_array($order, ['ASC','DESC'], true)) $order = 'DESC';

            $orderby_sql = 'ea.created_at';
            if ($orderby === 'post_title') $orderby_sql = 'p.post_title';

            $where = '1=1';
            $params = [];

            if ($metric !== '') { $where .= ' AND ea.metric_type = %s'; $params[] = $metric; }
            if ($post_type !== '') {
                // Usa COALESCE para funcionar mesmo se o backfill ainda não tiver preenchido ea.post_type
                $where .= ' AND COALESCE(NULLIF(ea.post_type, \'\'), p.post_type) = %s';
                $params[] = $post_type;
            }
            if ($year > 0)      { $where .= ' AND YEAR(ea.created_at) = %d'; $params[] = $year; }
            if ($month >= 1 && $month <= 12) { $where .= ' AND MONTH(ea.created_at) = %d'; $params[] = $month; }

            if ($search !== '') {
                if (ctype_digit($search)) {
                    $where .= ' AND (ea.post_id = %d OR p.post_title LIKE %s)';
                    $params[] = (int)$search;
                    $params[] = '%' . $wpdb->esc_like($search) . '%';
                } else {
                    $where .= ' AND p.post_title LIKE %s';
                    $params[] = '%' . $wpdb->esc_like($search) . '%';
                }
            }

            $count_sql = "SELECT COUNT(*) FROM {$table} ea LEFT JOIN {$posts} p ON p.ID = ea.post_id WHERE {$where}";
            $this->total_items = (int) $wpdb->get_var($wpdb->prepare($count_sql, $params));

            $optional_cols = ['user_ip_raw','geo_city','geo_region','geo_country','referrer_url','utm_source','utm_medium','utm_campaign'];
            $select_parts = [
                'ea.post_id',
                ($this->table_has_column($table, 'post_type') ? 'ea.post_type AS post_type' : 'p.post_type AS post_type'),
                'ea.metric_type',
                'ea.device_type',
                'ea.created_at',
                'p.post_title',
            ];
            foreach ($optional_cols as $col) {
                if ($this->table_has_column($table, $col)) {
                    $select_parts[] = 'ea.' . $col;
                } else {
                    $select_parts[] = 'NULL AS ' . $col;
                }
            }
            $select_sql = implode(",
                       ", $select_parts);

            $items_sql = "
                SELECT {$select_sql}
                FROM {$table} ea
                LEFT JOIN {$posts} p ON p.ID = ea.post_id
                WHERE {$where}
                ORDER BY {$orderby_sql} {$order}
                LIMIT %d OFFSET %d
            ";
            $items_params = array_merge($params, [$per_page, $offset]);
            $this->items = $wpdb->get_results($wpdb->prepare($items_sql, $items_params));

            $this->_column_headers = [$this->get_columns(), [], $this->get_sortable_columns()];
            $this->set_pagination_args(['total_items' => $this->total_items, 'per_page' => $per_page]);
        }

        public function column_default($item, $column_name) {
            switch ($column_name) {
                case 'post':
                    $title = $item->post_title ? $item->post_title : '(sem título)';
                    $label = esc_html($title) . ' (#' . (int)$item->post_id . ')';
                    $edit  = get_edit_post_link((int)$item->post_id);
                    return $edit ? '<a href="' . esc_url($edit) . '">' . $label . '</a>' : $label;

                case 'post_type':
                    return !empty($item->post_type) ? esc_html($item->post_type) : '—';

                case 'metric':
                    return esc_html($item->metric_type);

                case 'device':
                    return esc_html($item->device_type);

                case 'geo':
                    $city = !empty($item->geo_city) ? $item->geo_city : '';
                    $reg  = !empty($item->geo_region) ? $item->geo_region : '';
                    $cty  = !empty($item->geo_country) ? $item->geo_country : '';
                    $label = trim($city . ($city && $reg ? '/' : '') . $reg);
                    if ($cty) $label = trim($label . ($label ? ' - ' : '') . $cty);
                    return $label ? esc_html($label) : '—';

                case 'origin':
                    return $this->origin_label($item);

                case 'ip':
                    return !empty($item->user_ip_raw) ? esc_html($item->user_ip_raw) : '—';

                case 'date':
                    $dt = !empty($item->created_at) ? mysql2date('d/m/Y H:i:s', $item->created_at) : '';
                    return $dt ? esc_html($dt) : '—';

                default:
                    return '';
            }
        }

        public function get_total_items() {
            return $this->total_items;
        }
    }
}

new WP_Event_Analytics_Core();
