{
  description = "boxcryptor-recovery: offline decryption of Boxcryptor 2.x trees, file contents and file names";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/6f06d204d8f2d8761d9da78778745974a3216381";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      python = pkgs: pkgs.python3.withPackages (ps: [ ps.cryptography ]);
      runner = pkgs: pkgs.writeShellScriptBin "boxcryptor-recovery" ''
        exec ${python pkgs}/bin/python3 -I ${./decrypt_tree.py} "$@"
      '';
    in {
      packages = forAll (pkgs: { default = runner pkgs; });

      # From the directory that holds key.bckey (and optionally pass.txt):
      #   nix run github:<you>/boxcryptor-recovery -- --dry-run '<encrypted root dir>'
      apps = forAll (pkgs: {
        default = { type = "app"; program = "${runner pkgs}/bin/boxcryptor-recovery"; };
      });

      # Development shell: python + cryptography + file(1); run the tests with
      #   nix develop -c python3 -I -m unittest discover -s tests -v
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ (python pkgs) pkgs.file ];
          shellHook = ''
            echo "boxcryptor-recovery dev shell.  Tests: python3 -I -m unittest discover -s tests -v"
            echo "Never clone or copy this repo next to your key export or your encrypted data: a path flake"
            echo "is copied to /nix/store in full.  Keep keys and data in their own directory."
          '';
        };
      });
    };
}
