// Optional. The pages read without it. Loads the index the build wrote and filters it in the page.
(function () {
  var script = document.currentScript;
  var form = document.getElementById('search');
  var input = document.getElementById('q');
  var out = document.getElementById('results');
  if (!script || !form || !input || !out) return;
  var root = script.src.replace(/search\.js([?#].*)?$/, '');
  var pages = null;
  form.hidden = false;
  form.addEventListener('submit', function (e) {
    e.preventDefault();
  });
  function show(list) {
    out.textContent = '';
    list.forEach(function (p) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = root + p.path;
      a.textContent = p.title;
      li.appendChild(a);
      out.appendChild(li);
    });
  }
  input.addEventListener('input', function () {
    var term = input.value.trim().toLowerCase();
    if (!term) {
      show([]);
      return;
    }
    var run = function () {
      show(
        pages.filter(function (p) {
          return (p.title + ' ' + p.text).toLowerCase().indexOf(term) !== -1;
        })
      );
    };
    if (pages) {
      run();
      return;
    }
    fetch(root + 'index.json')
      .then(function (r) {
        return r.json();
      })
      .then(function (j) {
        pages = j;
        run();
      });
  });
})();
