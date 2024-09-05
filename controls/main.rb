# copyright: 2018, The Authors

title "macOS Simple CIS example"

control 'login-1.0' do
  impact 1.0
  title 'Asegurarse de que el inicio de sesión automático está deshabilitado'
  desc 'El inicio de sesión automático debería estar deshabilitado para evitar que el sistema sea accesible sin autenticación.'
  describe command("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser") do
    its('exit_status') { should eq 1 }
  end
end

control 'screensaver-1.0' do
  impact 1.0
  title 'Asegurarse de que se requiere contraseña después de suspender o activar el salvapantallas'
  desc 'Requerir una contraseña después de que el sistema sale del modo de suspensión o el salvapantallas está habilitado para proteger el acceso no autorizado.'

  # Verificar si la configuración está presente
  describe command("defaults read com.apple.screensaver askForPassword") do
    its('stdout.strip') { should eq '1' }
  end

  # Si la configuración no está presente, aplicar remediación
  if command("defaults read com.apple.screensaver askForPassword").stdout.strip != '1'
    remediation_script = <<-EOH
      defaults write com.apple.screensaver askForPassword -int 1
    EOH

    describe bash(remediation_script) do
      its('exit_status') { should eq 0 }
    end

    # Volver a verificar que la configuración se aplicó correctamente
    describe command("defaults read com.apple.screensaver askForPassword") do
      its('stdout.strip') { should eq '1' }
    end
  end
end

control 'printer-sharing-1.0' do
  impact 1.0
  title 'Asegurarse de que compartir impresoras está deshabilitado'
  desc 'El compartir impresoras debería estar deshabilitado para reducir el riesgo de ataques remotos.'
  describe command("cupsctl | grep _share_printers") do
    its('stdout.strip') { should match /_share_printers=0/ }
  end
end

control 'ssh-1.0' do
  impact 1.0
  title 'Asegurarse de que el acceso remoto (SSH) está deshabilitado'
  desc 'El acceso remoto debe estar deshabilitado si no es necesario para reducir la posibilidad de ataques remotos.'
  
  # Verificar si el SSH (Remote Login) está deshabilitado
  describe command("sudo systemsetup -getremotelogin") do
    its('stdout.strip') { should match /Remote Login: Off/ }
  end

  # Si el SSH está habilitado, aplicar remediación
  if command("sudo systemsetup -getremotelogin").stdout.strip != 'Remote Login: Off'
    remediation_script = <<-EOH
      sudo systemsetup -setremotelogin off
    EOH

    describe bash(remediation_script) do
      its('exit_status') { should eq 0 }
    end

    # Verificar nuevamente que SSH esté deshabilitado después de la remediación
    describe command("sudo systemsetup -getremotelogin") do
      its('stdout.strip') { should match /Remote Login: Off/ }
    end
  end
end


control 'file-sharing-1.0' do
  impact 1.0
  title 'Asegurarse de que compartir archivos está deshabilitado'
  desc 'El compartir archivos debería estar deshabilitado para evitar el acceso no autorizado a los archivos.'
  describe command("launchctl list | grep com.apple.AppleFileServer") do
    its('exit_status') { should eq 1 }
  end
  describe command("launchctl list | grep com.apple.smbd") do
    its('exit_status') { should eq 1 }
  end
end

control 'bluetooth-1.0' do
  impact 0.5
  title 'Asegurarse de que Bluetooth está deshabilitado si no es necesario'
  desc 'Bluetooth debería estar deshabilitado para minimizar la superficie de ataque.'
  describe command("defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState") do
    its('stdout.strip') { should eq '0' }
  end
end

control 'firewall-1.1' do
  impact 1.0
  title 'Asegurarse de que el firewall está configurado correctamente'
  desc 'El firewall debe estar activado y configurado para bloquear conexiones no autorizadas.'
  describe command("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate") do
    its('stdout.strip') { should match /Firewall is enabled/ }
  end
  describe command("/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall") do
    its('stdout.strip') { should match /Block all is off/ }
  end
end

control 'gatekeeper-1.0' do
  impact 1.0
  title 'Asegurarse de que Gatekeeper está habilitado'
  desc 'Gatekeeper debería estar habilitado para restringir la instalación de aplicaciones a aquellas verificadas.'
  describe command("spctl --status") do
    its('stdout.strip') { should match /assessments enabled/ }
  end
end

control 'system-extensions-1.0' do
  impact 1.0
  title 'Asegurarse de que las extensiones del sistema están en modo de seguridad completa'
  desc 'Las extensiones del sistema deberían estar configuradas en el modo de seguridad completa para proteger contra la carga de software malicioso.'

  # Verificar si la configuración de consentimiento de extensiones del kernel está habilitada
  describe command("spctl kext-consent status") do
    its('stdout.strip') { should match /Kernel Extension User Consent: ENABLED/ }
  end
end

