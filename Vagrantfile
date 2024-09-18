Vagrant.configure("2") do |config|
  config.nfs.functional = false
  config.vm.synced_folder "./", "/vagrant", type: "virtiofs"

  config.vm.define "target" do |target|
    target.vm.hostname = "target"
    target.vm.network :private_network, :ip => '10.10.10.10'
    target.vm.box = "generic/debian12"
    target.vm.provider "libvirt" do |vb|
        vb.memory = "512"
        vb.cpus = "2"
        vb.memorybacking :access, :mode => "shared"
    end
    target.vm.provision :ansible do |a|
      a.playbook = "vagrant/target.yml"
    end

  end

  config.vm.define "scanner" do |scanner|
    scanner.vm.hostname = "scanner"
    scanner.vm.network :private_network, :ip => '10.10.10.11'
    scanner.vm.box = "generic/debian12"
    scanner.vm.provider "libvirt" do |vb|
        vb.memory = "512"
        vb.cpus = "2"
        vb.memorybacking :access, :mode => "shared"
    end
    scanner.vm.provision :ansible do |a|
      a.playbook = "vagrant/scanner.yml"
    end

  end
end
