{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  # See full reference at https://devenv.sh/reference/options/
  languages.rust = {
    enable = true;
    channel = "stable";
  };

  packages = with pkgs; [
    rust-analyzer
    cargo-nextest
    openssl
  ];

  profiles.user.zevisert.module = let
    attrs = lib.concatMapAttrsStringSep " " lib.toShellVar {
      service = "openrouter";
      project = baseNameOf config.devenv.root;
    };
    opencode = pkgs.writeShellScriptBin "opencode" ''
      KEY=$(${lib.getExe' pkgs.oo7 "oo7-cli"} lookup --secret-only ${attrs} 2>/dev/null)
      if [ -z "$KEY" ]; then
        KEY=$(${lib.getExe' pkgs.systemd "systemd-ask-password"} "Enter OpenRouter API Key for ${attrs}:")

        if [ -n "$KEY" ]; then
          echo "$KEY" | ${lib.getExe' pkgs.oo7 "oo7-cli"} store 'openrouter@${config.devenv.root}' ${attrs}
        else
          echo "Error: No key provided." >&2
          exit 1
        fi
      fi

      OPENROUTER_API_KEY="$KEY" exec -a opencode ${lib.getExe pkgs.opencode} "$@"
    '';
  in {
    packages = [opencode] ++ config.packages;
    opencode = {
      enable = true;
      skills = let
        agent-skills = pkgs.fetchFromGitHub {
          owner = "addyosmani";
          repo = "agent-skills";
          tag = "0.6.3";
          hash = "sha256-S0rqJjcyC6MQo4pYLHws1jZXgr7Knqbyv+u95mg9cUE=";
        };
      in
        lib.pipe "${agent-skills}/skills" [
          builtins.readDir
          (lib.attrsets.filterAttrs (name: type: type == "directory"))
          (lib.attrsets.mapAttrs
            (name: type: builtins.toPath "${agent-skills}/skills/${name}"))
        ];
    };
  };
}
