param (
    [Parameter(Mandatory = $true)][string]$fileToSign,
    [Parameter(Mandatory = $true)][string]$SettingsFile
#    [string]$ComputerName = $env:computername,
#    [string]$username = $(throw "-username is required."),
#    [string]$password = $( Read-Host -asSecureString "Input password" ),
#    [switch]$SaveData = $false
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing


$CONFIG = Get-Content -Raw -Path $SettingsFile | ConvertFrom-Json
Write-Output $CONFIG.trustStorePath
Write-Debug $CONFIG

$LASTWIDGETROW = 70
$WIDGETSPACE = 20
$WIDGETSPACEEXTENDED = 70
#$WIDGETSPACETINY = 20


$Title = 'Digitally sign binary'
$Subtitle = 'You are about to leave an auditable trace by signing this file:'

# Imaginary vertical line that divides widgets with values we're dealing with
$ValueOffset = 150


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

#$FilePathLabel = New-Object system.Windows.Forms.Label
#$FilePathLabel.text = "Path:"
#$FilePathLabel.AutoSize = $true
#$FilePathLabel.width = 25
#$FilePathLabel.height = 10
#$FilePathLabel.location = New-Object System.Drawing.Point(20, $LASTWIDGETROW)
#$FilePathLabel.Font = 'Microsoft Sans Serif,14,style=Bold'

#$FilePath = New-Object system.Windows.Forms.Label
$FilePath = New-Object system.Windows.Forms.TextBox
$FilePath.text = $fileToSign
#$FilePath.BorderStyle = [System.Windows.Forms.FormBorderStyle]::None
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

$LASTWIDGETROW += $WIDGETSPACE
#--------------------------------------------------

$Separator = New-Object system.Windows.Forms.Label
$Separator.BorderStyle = [System.Windows.Forms.FormBorderStyle]::Fixed3D
$Separator.AutoSize = $false
$Separator.Anchor = 'Right'
#$Separator.Anchor = 'Left,Top,Right'
$Separator.Height = 2
#$Separator.Width = 100
$Separator.location = New-Object System.Drawing.Point(0, $LASTWIDGETROW)

$LASTWIDGETROW += $WIDGETSPACE
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
#$Separator,
$TrustStoreLabel, $TrustStoreValue,
$PasswordLabel, $PasswordValue,
#$ConfirmationLabel, $ConfirmationLabelEx
$ConfirmationLabel, $ConfirmationValue
))

[void]$SignForm.ShowDialog()


# Start-Process <path to exe> -NoNewWindow -Wait


#$output = ping.exe example.com | Out-String