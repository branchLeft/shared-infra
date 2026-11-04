// Optional. The pages read without it. Filters the index the build wrote, in the page.
(function () {
  var form = document.getElementById('search');
  var input = document.getElementById('q');
  var out = document.getElementById('results');
  var script = document.currentScript;
  if (!form || !input || !out || !script || !window.elasticlunr || !window.searchIndex) return;
  var root = script.src.replace(/search\.js([?#].*)?$/, '');
  var index = window.elasticlunr.Index.load(window.searchIndex);
  form.hidden = false;
  form.addEventListener('submit', function (e) {
    e.preventDefault();
  });
  input.addEventListener('input', function () {
    var term = input.value.trim();
    out.textContent = '';
    if (!term) return;
    index.search(term, { expand: true }).forEach(function (hit) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = hit.ref;
      a.textContent = hit.doc.title || hit.ref;
      li.appendChild(a);
      out.appendChild(li);
    });
  });
})();
