document.addEventListener('DOMContentLoaded', function () {
  // Redundância simples (não é a fonte principal do tracking)
  try {
    if (!window.weaPostId || !window.weaAjax) return;
    var img = new Image();
    img.src = window.weaAjax + '?action=wea_track&as_pixel=1&metric_type=view&post_id=' + window.weaPostId;
  } catch (e) {}
});
