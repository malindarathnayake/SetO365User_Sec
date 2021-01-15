##################################################### ABOUT THIS SCRIPT #####################################################
#                                                                                                                           #
# File name: Set_Security.ps1                                                                                               #
# Location:  IT Glue                                                                                                        #
# Author:    malinda Rathnayake, mrathnayake@wcatech.com                                                                    #
# Date:      01/2021                                                                                                       #
#                                                                                                                           #
#############################################################################################################################
# Usage - 
# This script supports Modern Auth and MFA and Does not use any Cred caching for security, 
# You will need to install the reveant modules Exchnage online and MSOL
#
#  Install-Module -Name ExchangeOnlineManagement
#  Install-Module MSOnline or Install-Module AzureADPreview
#
#   To Process all users 
#                        .\Set_security.ps1 -ProcessallUsers $true
#
#   To process just one User
#                        .\Set_security.ps1 -SingleUser $true, 
#                                                              it will prompt you to enter the UPN of the user
#
#   To view information on one user 
#                        .\Set_security.ps1 -view_info_SingleUser $true, 
#                                                                       it will prompt you to enter the UPN of the user
#
param (
    [string]$ProcessallUsers,
    [string]$SingleUser,
    [string]$view_info_SingleUser
)
function Set_security_Settings($UserPrincipalName)  {
Write-Host "Auditing Polcies" -ForegroundColor Green -BackgroundColor Black
Set-Mailbox -identity $UserPrincipalName -auditlogagelimit 180
Set-Mailbox -identity $UserPrincipalName -AuditAdmin UpdateCalendarDelegation,UpdateFolderPermissions,Copy,SendAs,Update,SendOnBehalf,MoveToDeletedItems,HardDelete,SoftDelete,UpdateInboxRules,Move,Create
Set-Mailbox -identity $UserPrincipalName -AuditDelegate FolderBind,UpdateFolderPermissions,SendAs,Update,SendOnBehalf,MoveToDeletedItems,HardDelete,SoftDelete,UpdateInboxRules,Move,Create
Set-Mailbox -identity $UserPrincipalName -AuditOwner UpdateCalendarDelegation,UpdateFolderPermissions,MailboxLogin,Update,MoveToDeletedItems,HardDelete,SoftDelete,UpdateInboxRules,Move,Create
Write-Host "Disable Remote Powershell"  -ForegroundColor Green -BackgroundColor Black
set-user -identity $UserPrincipalName -RemotePowerShellEnabled $false
Write-Host "Disable POP, IMAP"  -ForegroundColor Green -BackgroundColor Black
Set-CasMailbox -identity $UserPrincipalName -PopEnabled $false -ImapEnabled $false
}
function Get_security_Settings($UserPrincipalName) {
$Userviewinfo = new-object psobject
$Usersecinfo = New-Object -TypeName psobject 
$Usersecinfo | Add-Member -MemberType NoteProperty -Name User_identity -Value $mbx.identity
$Usersecinfo | Add-Member -MemberType NoteProperty -Name User_identity -Value $mbx.identity
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Mailbox_Owners_actions_Audited -Value $mbx.AuditOwner
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Delegated_Users_Actions_Audited -Value $mbx.AuditDelegate
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Admin_user_actions_Audited -Value $mbx.AuditAdmin
$Userviewinfo | fl
$Userviewinfo | Export-Csv "'$Usersecinfo.User_identity'-SecurityReport.csv"
}

#
$currentsessions = Get-PSSession |? Name -Like 'ExchangeOnline*' |? State -EQ Opened
#
if ($currentsessions){
Write-Host "EXOP PSSession Active"}else{
Connect-ExchangeOnline
Connect-MsolService
}
#debug
#$globaladmins = Get-MsolRoleMember -RoleObjectId $(Get-MsolRole -RoleName "Company Administrator").ObjectId
#
#if ($user -in $globaladmins.EmailAddress){Write-Host "This is an admin"}else {Write-Host "This is not an admin"}
#
#---------Script-----------------------
#
$globaladminlist = Get-MsolRoleMember -RoleObjectId $(Get-MsolRole -RoleName "Company Administrator").ObjectId
#
#
if ($ProcessallUsers){Write-Host "Processing all users"

$userMailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize unlimited

ForEach ($mailbox in $userMailboxes)
{
$DisplayName = $mailbox.DisplayName

Write-Host ""
    if ($mailbox.UserPrincipalName -in $globaladminlist.EmailAddress)
        {
        Write-Host "Processing $DisplayName - *******This is an Global admin - Skiped********" -ForegroundColor Red -BackgroundColor Black
        Write-Host "  "
        continue
        }
    Else
        {
        Write-Host "Processing $DisplayName - Setting Security Profile"  -ForegroundColor Blue  -BackgroundColor Black
        Write-Host "  "
        Set_security_Settings -UserPrincipalName $mailbox.UserPrincipalName
        }
    }
}
#
if ($SingleUser){
#
$User = Read-Host "Enter User principle name"
#
Write-Host "Processing one user UPN - $User"
#
    if ($User -in $globaladmins.EmailAddress)
        {
        Write-Host "Processing $DisplayName - *******This is an Global admin - Skiped********" -ForegroundColor Red -BackgroundColor Black
        Write-Host "  "
        continue
        }
    Else
        {
        Write-Host "Processing $DisplayName - Setting Security Profile"  -ForegroundColor Blue  -BackgroundColor Black
        Write-Host "  "
        Set_security_Settings -UserPrincipalName $User
        }
    }

if ($view_info_SingleUser){

$User = Read-Host "Enter User principle name"
$mbx = Get-Mailbox $User
$userinfo = Get-User $User
$usercasinfo = Get-CASMailbox $User

$Usersecinfo = new-object psobject

$Usersecinfo = New-Object -TypeName psobject 
$Usersecinfo | Add-Member -MemberType NoteProperty -Name User_identity -Value $mbx.identity
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Mailbox_Owners_actions_Audited -Value $mbx.AuditOwner
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Delegated_Users_Actions_Audited -Value $mbx.AuditDelegate
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Admin_user_actions_Audited -Value $mbx.AuditAdmin
$Usersecinfo | Add-Member -MemberType NoteProperty -Name Remote_PowerShell_Enabled -Value $userinfo.RemotePowerShellEnabled
$Usersecinfo | Add-Member -MemberType NoteProperty -Name POP-Enabled -Value $usercasinfo.PopEnabled
$Usersecinfo | Add-Member -MemberType NoteProperty -Name IMAP-Enabled -Value $usercasinfo.ImapEnabled
$Usersecinfo | Add-Member -MemberType NoteProperty -Name OWA-Enabled -Value $usercasinfo.OWAEnabled
$Usersecinfo | Add-Member -MemberType NoteProperty -Name SMTPClient_Auth-Disabled -Value $usercasinfo.SmtpClientAuthenticationDisabled
$Usersecinfo | fl

}