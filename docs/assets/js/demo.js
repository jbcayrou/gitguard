// "Five attacks": the panels are rendered by Jekyll from _data/attacks.yml;
// this only switches the visible one and keeps the tabs keyboard-friendly.
(function(){
  "use strict";
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tabs [role=tab]'));
  var panels = Array.prototype.slice.call(document.querySelectorAll('.demo[role=tabpanel]'));
  if (!tabs.length) return;
  function select(name){
    tabs.forEach(function(t){ t.setAttribute("aria-selected", t.getAttribute("data-a")===name ? "true" : "false"); });
    panels.forEach(function(p){ p.hidden = (p.id !== "demo-"+name); });
  }
  tabs.forEach(function(t){
    t.addEventListener("click", function(){ select(t.getAttribute("data-a")); });
    t.addEventListener("keydown", function(e){
      var i = tabs.indexOf(t), n = null;
      if (e.key==="ArrowRight") n = tabs[(i+1)%tabs.length];
      else if (e.key==="ArrowLeft") n = tabs[(i-1+tabs.length)%tabs.length];
      if (n){ e.preventDefault(); n.focus(); select(n.getAttribute("data-a")); }
    });
  });
})();
