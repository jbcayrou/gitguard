// Interactive demo of the "Five attacks" section: fills the three terminals for the selected tab.
(function(){
  "use strict";
  var RULE = "────────────────────────────────────────────────────────";
  function L(c,s){ return {c:c, s:(s===undefined?"":s)}; }
  function esc(t){ return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

  // Reusable host-side fragments
  var refuseHead = [ L("hr",RULE),
    L("w","! gitguard: ~/work/api/.git has changed since the last trust") ];
  var refuseTail = [ L(""), L("hr",RULE),
    L("hint","  If legitimate:  gitguard trust   Otherwise:  gitguard restore"),
    L("x","✗ gitguard: refusing to run git.") ];
  function refuse(changes, diff){
    return refuseHead.concat(changes, diff||[], refuseTail);
  }
  var cleanStatus = [ L("","On branch main"), L("","nothing to commit, working tree clean") ];

  var ATTACKS = {
    hook: {
      story: "The sandbox drops an executable file into .git/hooks/. git runs pre-commit, pre-push and a dozen others with no prompt, every time.",
      sandbox: [
        L("dim","# running as the agent, inside the mounted repo"),
        L("p","$ cat > .git/hooks/pre-commit <<'EOF'"),
        L("","  #!/bin/sh"),
        L("pwn","  # read credentials from $HOME, send them out, stay quiet"),
        L("","EOF"),
        L("p","$ chmod +x .git/hooks/pre-commit")
      ],
      without: [
        L("p","$ git commit -m \"fix typo\""),
        L("pwn","[pre-commit] credentials copied to attacker host"),
        L("","[main 3f2a9c1] fix typo"),
        L("dim"," 1 file changed, 1 insertion(+)")
      ],
      with: [ L("p","$ git commit -m \"fix typo\"") ].concat(
        refuse([ L("add","  added     hooks/pre-commit") ]) )
    },
    config: {
      story: "No hook needed. A single line in .git/config, core.fsmonitor, names a command git launches on almost every operation.",
      sandbox: [
        L("dim","# one key is enough"),
        L("p","$ git config core.fsmonitor 'sh -c \"...\"'")
      ],
      without: [
        L("p","$ git status"),
        L("pwn","[fsmonitor] launched: payload running as you"),
        L("","On branch main"),
        L("dim","nothing to commit, working tree clean")
      ],
      with: [ L("p","$ git status") ].concat( refuse(
        [ L("mod","  modified  config") ],
        [ L(""), L("","  diff of ~/work/api/.git/config:"), L("hint","  @@ -5,3 +5,4 @@"),
          L("","   \tignorecase = true"), L("","   \tprecomposeunicode = true"),
          L("add","  +\tfsmonitor = sh -c \"...\"") ] ) )
    },
    hookspath: {
      story: "If the sandbox can only write the work tree, not .git, it still wins: core.hooksPath points git at a hooks directory that lives in the tree.",
      sandbox: [
        L("p","$ mkdir .githooks"),
        L("p","$ printf '...' > .githooks/pre-push"),
        L("p","$ git config core.hooksPath .githooks")
      ],
      without: [
        L("p","$ git push"),
        L("pwn","[pre-push] payload running from .githooks/"),
        L("dim","Everything up-to-date")
      ],
      with: [ L("p","$ git push") ].concat( refuse(
        [ L("mod","  modified  config"), L("add","  added     wt:.githooks/pre-push") ],
        [ L(""), L("","  diff of ~/work/api/.git/config:"), L("hint","  @@ -5,3 +5,4 @@"),
          L("","   \tprecomposeunicode = true"), L("add","  +\thooksPath = .githooks") ] ) )
    },
    nested: {
      story: "A second repository planted in a subdirectory. git reads its config the moment a gitlink exists in the index, which an ordinary git add -A creates.",
      sandbox: [
        L("p","$ git init vendor/lib"),
        L("p","$ git -C vendor/lib config core.fsmonitor '...'"),
        L("p","$ git -C vendor/lib commit --allow-empty -m x")
      ],
      without: [
        L("p","$ git add -A"),
        L("dim","warning: adding embedded git repository: vendor/lib"),
        L("p","$ git status"),
        L("pwn","[vendor/lib] nested config executed")
      ],
      with: [
        L("p","$ git add -A"),
        L("dim","warning: adding embedded git repository: vendor/lib"),
        L("p","$ git status"),
        L("hr",RULE),
        L("x","✗ gitguard: nested repository: vendor/lib/.git — a gitlink for this"),
        L("x","  directory exists in the index, git will execute its config."),
        L("dim","  If it is your own vendored repository: inspect its config and hooks,"),
        L("dim","  declare it in .gitmodules, git submodule absorbgitdirs, gitguard trust."),
        L("dim","  Otherwise delete vendor/lib/.git first, then git rm --cached lib."),
        L("x","✗ gitguard: refusing to run git.")
      ]
    },
    redirect: {
      story: "The boldest move: replace .git with a one-line gitdir: file pointing at a directory the sandbox controls, config and hooks included.",
      sandbox: [
        L("p","$ cp -r .git evil/repo.git"),
        L("p","$ rm -rf .git"),
        L("p","$ echo 'gitdir: ./evil/repo.git' > .git")
      ],
      without: [
        L("p","$ git log --oneline -1"),
        L("pwn","[evil/repo.git] hooks and config now in control"),
        L("dim","3f2a9c1 fix typo")
      ],
      with: [
        L("p","$ git log --oneline -1"),
        L("x","✗ gitguard: ~/work/api/.git points inside the work tree"),
        L("dim","  (~/work/api/evil/repo.git)"),
        L("x","✗ gitguard: refusing to run git.")
      ]
    }
  };

  var sb = document.getElementById("sandbox");
  var pw = document.getElementById("pane-without");
  var pg = document.getElementById("pane-with");
  var story = document.getElementById("story");
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tabs [role=tab]'));
  var demo = document.getElementById("demo");

  function render(el, lines){
    el.innerHTML = lines.map(function(x){
      var cls = x.c ? ' class="'+x.c+'"' : '';
      return '<span'+cls+'>'+esc(x.s)+'</span>';
    }).join("\n");
  }

  function select(name){
    var a = ATTACKS[name]; if(!a) return;
    tabs.forEach(function(t){
      var on = t.getAttribute("data-a")===name;
      t.setAttribute("aria-selected", on?"true":"false");
      if(on) demo.setAttribute("aria-labelledby", t.id);
    });
    story.textContent = a.story;
    render(sb, a.sandbox);
    render(pw, a.without);
    render(pg, a.with);
  }

  tabs.forEach(function(t){
    t.addEventListener("click", function(){ select(t.getAttribute("data-a")); });
    t.addEventListener("keydown", function(e){
      var i = tabs.indexOf(t), n = null;
      if(e.key==="ArrowRight") n = tabs[(i+1)%tabs.length];
      else if(e.key==="ArrowLeft") n = tabs[(i-1+tabs.length)%tabs.length];
      if(n){ e.preventDefault(); n.focus(); select(n.getAttribute("data-a")); }
    });
  });
  select("hook");
})();
