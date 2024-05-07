let pkgs = import ((import<nixpkgs>{}).fetchFromGitHub
  (with (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.nixpkgs.locked; {
    inherit owner repo rev;
    sha256 = narHash;
  })) {}; in with pkgs;

let
  isGit = s: (builtins.substring 0 4 s) == "git+";
  contains = needle: haystack: (builtins.length (lib.splitString needle haystack)) > 1;
  stripPrefix = s: builtins.substring 4 (builtins.stringLength s) s;
  splitBy = sep: idx: s: (builtins.elemAt (lib.splitString sep s) idx);
  gitURL = s: splitBy "?" 0 (stripPrefix s);
  gitBranch = s: if (contains "?branch=" s)
    then splitBy "#" 0 (splitBy "?branch=" 1 (stripPrefix s))
    else if (contains "?tag=" s)
    then splitBy "#" 0 (splitBy "?tag=" 1 (stripPrefix s))
    else null;
  gitRev = s: splitBy "#" 1 (stripPrefix s);
  gitHash = s: (builtins.fetchGit ((maybeRef (gitBranch s)) // { url = gitURL s; rev = gitRev s; })).narHash;
  maybeRef = s: if s != null then { ref = s; } else {};
  packages = builtins.filter (x: x?source && isGit x.source) (builtins.fromTOML (builtins.readFile ./Cargo.lock)).package;
in

builtins.foldl' (f: x: f // {
  "${x.name+"-"+x.version}" = {
    url = x.source;
    narHash = gitHash x.source;
  };
}) {} packages
