param (
    [Parameter(Mandatory = $true, HelpMessage='Path to file that needs to be signed')][string]$fileToSign,
    [Parameter(Mandatory = $true, HelpMessage='Path to file where settings are stored')][string]$SettingsFile,
    [Parameter(HelpMessage='File to which the signature will be written')][string]$SignaturePath='signature.asc'
)


# We expect a settings file, like the JSON below. If the file is not given, the script fails
#{
#    "trustStorePath": "/etc/truststore-playground.jks",
#    "signServerUrl": "signservice.com:443",
#    "signServerWorker": "OpenPGPSignerMaven",
#    "signServerKeyId": "1bcde241252",
#    "signClientPath": "C:\\programs\\signserver\\bin"
#}



Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing


$CONFIG = Get-Content -Raw -Path $SettingsFile | ConvertFrom-Json

$LASTWIDGETROW = 70
$WIDGETSPACE = 20
$WIDGETSPACEEXTENDED = 70


$Title = 'Digitally sign binary'
$Subtitle = 'You are about to leave an auditable trace by signing this file:'

# Imaginary vertical line that divides widgets with values we're dealing with
$ValueOffset = 150

# these will be used as an additional attention-check.
$ConfirmationWords = @("Responsible", "Consequence", "Implications", "Double-check",
                       "Understand", "Competence", "Attention", "Careful")

[System.Windows.Forms.Application]::EnableVisualStyles()

$SignForm = New-Object system.Windows.Forms.Form
$SignForm.ClientSize = '450, 480'
$SignForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Fixed3D
$SignForm.Text = $Title
$SignForm.Icon = [System.Drawing.SystemIcons]::Shield


$MainTitle = New-Object system.windows.Forms.Label
$MainTitle.Text = $Title
$MainTitle.AutoSize = $true
$MainTitle.Width = 25
$MainTitle.Height = 10
$MainTitle.Font = 'Microsoft Sans Serif,13'
$MainTitle.location = New-Object System.Drawing.Point(20, 20)

$Prologue = New-Object system.Windows.Forms.Label
$Prologue.text = $Subtitle
$Prologue.AutoSize = $false
$Prologue.width = 450
$Prologue.height = 20
$Prologue.location = New-Object System.Drawing.Point(20, 50)
$Prologue.Font = 'Microsoft Sans Serif,10'

$FilePath = New-Object system.Windows.Forms.TextBox
$FilePath.text = $fileToSign
$FilePath.Width = 390
$FilePath.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$FilePath.Font = 'Microsoft Sans Serif,20'
$FilePath.ReadOnly = $True

$LASTWIDGETROW += $WIDGETSPACEEXTENDED
#--------------------------------------------------

$ServerLabel = New-Object system.Windows.Forms.Label
$ServerLabel.text = "SignServer URL:"
$ServerLabel.AutoSize = $true
$ServerLabel.width = 25
$ServerLabel.height = 10
$ServerLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$ServerLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$ServerValue = New-Object system.Windows.Forms.Label
$ServerValue.text = $CONFIG.signServerUrl
$ServerValue.AutoSize = $true
$ServerValue.location = New-Object System.Drawing.Point($ValueOffset, $LASTWIDGETROW)
$ServerValue.Font = 'Microsoft Sans Serif,10'

$LASTWIDGETROW += $WIDGETSPACE
#--------------------------------------------------

$WorkerLabel = New-Object system.Windows.Forms.Label
$WorkerLabel.text = "Sign worker:"
$WorkerLabel.AutoSize = $true
$WorkerLabel.width = 25
$WorkerLabel.height = 10
$WorkerLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$WorkerLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$WorkerValue = New-Object system.Windows.Forms.Label
$WorkerValue.text = $CONFIG.signServerWorker
$WorkerValue.AutoSize = $true
$WorkerValue.location = New-Object System.Drawing.Point($ValueOffset, $LASTWIDGETROW)
$WorkerValue.Font = 'Microsoft Sans Serif,10'

$LASTWIDGETROW += $WIDGETSPACE
#--------------------------------------------------

$KeyIdLabel = New-Object system.Windows.Forms.Label
$KeyIdLabel.text = "Key ID:"
$KeyIdLabel.AutoSize = $true
$KeyIdLabel.width = 25
$KeyIdLabel.height = 10
$KeyIdLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$KeyIdLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$KeyIdValue = New-Object system.Windows.Forms.Label
$KeyIdValue.text = $CONFIG.signServerKeyId
$KeyIdValue.AutoSize = $true
$KeyIdValue.location = New-Object System.Drawing.Point($ValueOffset, $LASTWIDGETROW)
$KeyIdValue.Font = 'Microsoft Sans Serif,10'

$LASTWIDGETROW += $WIDGETSPACEEXTENDED
#--------------------------------------------------

$TrustStoreLabel = New-Object system.Windows.Forms.Label
$TrustStoreLabel.text = "Trust store:"
$TrustStoreLabel.AutoSize = $true
$TrustStoreLabel.width = 25
$TrustStoreLabel.height = 10
$TrustStoreLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$TrustStoreLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$TrustStoreValue = New-Object system.Windows.Forms.Label
$TrustStoreValue.text = $CONFIG.trustStorePath
$TrustStoreValue.AutoSize = $true
$TrustStoreValue.location = New-Object System.Drawing.Point($ValueOffset, $LASTWIDGETROW)
$TrustStoreValue.Font = 'Microsoft Sans Serif,10'

$LASTWIDGETROW += $WIDGETSPACE
#--------------------------------------------------

$PasswordLabel = New-Object system.Windows.Forms.Label
$PasswordLabel.text = "Password:"
$PasswordLabel.AutoSize = $true
$PasswordLabel.width = 25
$PasswordLabel.height = 10
$PasswordLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$PasswordLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$PasswordValue = New-Object system.Windows.Forms.TextBox
#$PasswordValue.AutoSize = $true
$PasswordValue.Width = 260
$PasswordValue.location = New-Object System.Drawing.Point($ValueOffset, $LASTWIDGETROW)
$PasswordValue.Font = 'Microsoft Sans Serif,10'
$PasswordValue.PasswordChar = [char]0x25CF  # big bold circle


$LASTWIDGETROW += $WIDGETSPACEEXTENDED
#--------------------------------------------------

# to increase awareness, we add another input there, each time a new word needs to be written down, to nudge
# the user towards being careful with what they do
$ConfirmationWord = $ConfirmationWords | Get-Random

# Because WinForms cannot have a label with formatting (like bold or italic), we use a RichTextBox with RTF
# contents, and change its style such that it looks like a label.
# NOTE the RTF syntax: \fs20 sets the font size to 20 units, \b begins a bold area, \b0 ends it
$ConfirmationLabel = New-Object system.Windows.Forms.RichTextBox
$ConfirmationLabel.Rtf = "{\rtf1\ansi \fs20 Type the word \b $ConfirmationWord \b0 in the box below to confirm:}"
$ConfirmationLabel.width = 390
$ConfirmationLabel.height = 20
$ConfirmationLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$ConfirmationLabel.ReadOnly = $true
$ConfirmationLabel.BorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$ConfirmationLabel.Enabled = $false  # this makes it non-selectable, it is gray - but that's acceptable
$LASTWIDGETROW += $WIDGETSPACE

$ConfirmationValue = New-Object system.Windows.Forms.TextBox
#$ConfirmationValue.AutoSize = $true
$ConfirmationValue.Width = 390
$ConfirmationValue.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
$ConfirmationValue.Font = 'Microsoft Sans Serif,10'
$ConfirmationValue.PasswordChar = [char]0x2764  # heart :-)


$LASTWIDGETROW += $WIDGETSPACEEXTENDED
#--------------------------------------------------







$cancelBtn = New-Object system.Windows.Forms.Button
#$cancelBtn.BackColor = "#82e09b"
$cancelBtn.text = "Quit"
$cancelBtn.width = 90
$cancelBtn.height = 30
$cancelBtn.location = New-Object System.Drawing.Point(210, 400)
$cancelBtn.Font = 'Microsoft Sans Serif,10'
$cancelBtn.ForeColor = "#000"
$cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$SignForm.CancelButton = $cancelBtn
$SignForm.Controls.Add($cancelBtn)

$signBtn = New-Object system.Windows.Forms.Button
$signBtn.BackColor = "#ff7b00"
$signBtn.text = "Sign"
$signBtn.width = 90
$signBtn.height = 30
$signBtn.location = New-Object System.Drawing.Point(320, 400)
$signBtn.Font = 'Microsoft Sans Serif,10'
$signBtn.ForeColor = "white"
#$signBtn.Image = [System.Drawing.SystemIcons]::Shield
$SignForm.Controls.Add($signBtn)





$SignForm.Controls.AddRange(@(
    $MainTitle, $Prologue,
    $FilePathLabel, $FilePath,
    $ServerLabel, $ServerValue,
    $WorkerLabel, $WorkerValue,
    $KeyIdLabel, $KeyIdValue
    $TrustStoreLabel, $TrustStoreValue,
    $PasswordLabel, $PasswordValue,
    $ConfirmationLabel, $ConfirmationValue
))

function SignFile($srcPath, $dstPath, $timeout) {

    if([string]::IsNullOrEmpty($PasswordValue.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please provide the trust store password", "More input required", 0, 'Exclamation')
        return
    }

    if($ConfirmationValue.Text -ne $ConfirmationWord) {
        $Message = @"
Please type $ConfirmationWord in the confirmation field.

This is a highly-sensitive operation, ensure you know what you are doing!
"@
        [System.Windows.Forms.MessageBox]::Show($Message, "Double-check your input", 0, 'Information')
        return
    }

    # provide some feedback in the UI, change the button label and color
    $signBtn.BackColor = "gray"
    $signBtn.text = "Signing ..."


    $urlParts = $($CONFIG.signServerUrl).split(':')
    $hostName = $urlParts[0]
    $port = $urlParts[1]

    # generate a name for a unique temporary file, where the output of the signclient will be stored for subsequent
    # analysis (will be useful if there are errors)
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $tempFile = "$env:TEMP\signgui_$timestamp.log"
    # +[System.IO.Path]::GetRandomFileName()



    $originalWorkingDir = Get-Location
    # if a path is relative, then we turn it into an absolute path, because SignClient doesn't work if launched
    # from a directory other than its own.
    If (-Not [System.IO.Path]::IsPathRooted($srcPath)) {$srcPath = Join-Path $originalWorkingDir $srcPath}
    If (-Not [System.IO.Path]::IsPathRooted($dstPath)) {$dstPath = Join-Path $originalWorkingDir $dstPath}

    # Here we form the command line that will be invoked, it might look like this, but note that relative paths
    # will be made absolute:
    # /usr/bin/signclient signdocument -workername OpenPGPSignerMaven -infile CmpRaComponent-2.1.5.jar -outfile signature.asc -host signservice-playground.ct.siemens.com -port 443 -truststore truststore-playground.jks -truststorepwd "123456" -clientside -digestalgorithm SHA256 -filetype PGP -extraoption DETACHED_SIGNATURE=TRUE -extraoption KEY_ALGORITHM=RSA -extraoption KEY_ID=E9498CD6F99ED951
    $command = 'signclient.cmd'
    $arguments = "signdocument -workername $($CONFIG.signServerWorker) -infile $srcPath -outfile $dstPath -host $hostName -port $port -truststore $($CONFIG.trustStorePath) -truststorepwd $($PasswordValue.Text) -clientside -digestalgorithm SHA256 -filetype PGP -extraoption DETACHED_SIGNATURE=TRUE -extraoption KEY_ALGORITHM=RSA -extraoption KEY_ID=$($CONFIG.signServerKeyId)"


    # uncomment the two lines below to simulate a successful signature
    #    $command = 'ping'
    #    $arguments = '8.8.8.8'
    # WATCH OUT: here we change the directory to the place where signclient is located, because it does not work
    #            otherwise. We set it back later, so the calling logic doesn't need to know about it.
    $process = Start-Process $command -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempFile -WorkingDirectory $CONFIG.signClientPath

    # go back to the original working directory, such that whatever logic invokes this script doesn't have to be
    # aware of the working directory changes.
    Set-Location $originalWorkingDir

    # load the contents of the file here, so we can put it in the messagebox later
    $output = Get-Content $tempFile


    if ($process.ExitCode -eq 0) {
        # everything is fine, make it green and keep going
        $signBtn.BackColor = "#82e09b"
        $signBtn.ForeColor = "#000"
        $signBtn.text = "Done"
        $operationStatus = "Signed successfully!"

        $message = @"
Digital signature saved to $dstPath.

The window will close and the pipeline will continue.
"@
        [System.Windows.Forms.MessageBox]::Show($message, $operationStatus, 0, 'Information')

        # nicely close the window after the messagebox is closed, and let the higher level logic take over
        $SignForm.Close()
    }
    else {
        # there was an error, make it red
        $signBtn.BackColor = "red"
        $signBtn.ForeColor = "white"
        $signBtn.text = "Error $($process.ExitCode)"
        $operationStatus = "Operation error"

        $message = @"
Diagnostic details in signclient's log:
$tempFile



$output
"@
        [System.Windows.Forms.MessageBox]::Show($message, $operationStatus, 0, 'Error')

        # After the messagebox is closed, we restore the button's properties, so the user can see that they
        # can try to sign again
        $signBtn.BackColor = "#ff7b00"
        $signBtn.text = "Sign"
    }


}



$signBtn.Add_Click({SignFile $fileToSign $SignaturePath 45})  # timeout is unused for now


[void]$SignForm.ShowDialog()