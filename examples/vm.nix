# The host configuration for the throwaway test VM.
#
#   nix build .#vm && ./result/bin/run-wazuh-agent-vm
#
# The agent points at 10.0.2.2, which is the host machine as seen from QEMU
# user mode networking. Run a Wazuh manager on the host and the agent reaches
# it without extra network setup.
#
# qemu-vm.nix is imported here rather than in flake.nix. It defines the
# virtualisation options that this file sets, so importing it here keeps the
# configuration evaluable on its own.
{
  lib,
  modulesPath,
  ...
}:
{
  imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

  services.wazuh-agent = {
    enable = true;
    manager.host = "10.0.2.2";
    manager.port = 1514;
    registration.port = 1515;
  };

  # This VM is a throwaway. Log in as root with the password wazuh.
  users.users.root.password = "wazuh";
  services.getty.autologinUser = "root";
  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "yes";

  networking.hostName = "wazuh-agent";
  networking.firewall.enable = false;

  virtualisation = {
    memorySize = 2048;
    diskSize = 8192;
    # Serial console. Type Ctrl-a x to quit QEMU.
    graphics = false;
    # Reach the VM over SSH at localhost:2222 from the host.
    forwardPorts = [
      {
        from = "host";
        host.port = 2222;
        guest.port = 22;
      }
    ];
  };

  system.stateVersion = lib.trivial.release;
}
