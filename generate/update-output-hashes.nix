let
  isGit = s: (builtins.substring 0 4 s) == "git+";
  packages =
    builtins.filter (x: x ? source && isGit x.source)
    (builtins.fromTOML (builtins.readFile ../Cargo.lock)).package;
  gitHash = source: let
    matched = builtins.elemAt (builtins.match ''git\+([^?]*)(\?(branch|tag)=([^#]*))?#(.*)'' source);
  in
    (builtins.fetchGit {
      url = matched 0;
      rev = matched 4;
    })
    .narHash;
in
  builtins.listToAttrs
  (map
    (package: {
      name = "${package.name + "-" + package.version}";
      value = {
        url = package.source;
        narHash = gitHash package.source;
      };
    })
    packages)
