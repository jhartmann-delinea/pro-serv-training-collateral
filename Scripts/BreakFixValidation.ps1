####################
# Set up Variables #
####################

$date = Get-Date -UFormat "%m%d%Y"
$fdate = Get-Date -UFormat "%Y"
$student = Read-Host -Prompt "Enter Student Name"

$file = "$PSScriptRoot\BreakFixResults_" + $student + "_" + $fdate + ".txt" # Will be changed to Read-Host later on

$BackupFiles = ""
$fail = 0 # Check for multiple Tasks

# Hashtables for tracking results
$Problem = [ordered]@{} 
$failures = [ordered]@{}

# Create a web request.
$HTTP_Request = [System.Net.WebRequest]::Create('https://app.delinealabs.com/SecretServer/')

$SqlServer    = 'APP\SQLEXPRESS' # SQL Server instance (HostName\InstanceName for named instance)
$Database     = 'SecretServer'      # SQL database to connect to 
#$SqlAuthLogin = 'test'            # SQL Authentication login
#$SqlAuthPw    = 'SuperSecret'     # SQL Authentication login password

####################
# Set up Functions #
####################

function Invoke($SQLString) {
    (Invoke-Sqlcmd -ConnectionString "Data Source=$SqlServer;Initial Catalog=$Database; Integrated Security=True;" -Query "$SQLString").ItemArray # Without ItemArray, headers are returned
}

function EchoOut($EchoString){
    echo $EchoString | Tee-Object -FilePath $file -Append
}



#
# Task #1 Display Overall Pass/Fail... DONE 
#
# Task #2 Display Which Problems failed... DONE
#

##############################
# Begin Problem 1 Evaluation #
##############################


#
# Task 1# Set svc_thy_app as dbo for SS DB... DONE
#
# Task #2 Verify password from Credential Manager matches password on SS App Pool... DONE
# 
# Task #3 Verify URL is reachable... DONE

# Query to show membership

$Problem["1"] = [ordered]@{}

$MemberQuery = "
SELECT  members.name as 'members_name', roles.name as 'roles_name',roles.type_desc as 'roles_desc',members.type_desc as 'members_desc'
FROM sys.database_role_members rolemem
INNER JOIN sys.database_principals roles
ON rolemem.role_principal_id = roles.principal_id
INNER JOIN sys.database_principals members
ON rolemem.member_principal_id = members.principal_id
where roles.name = 'db_owner' AND members.name like '%svc_thy_app%'"




# more secure windows authentication with current account
$Result =  Invoke($MemberQuery)

if ($Result -eq $null){ 
    $Problem["1"]["Permission Results"] = "FAIL"
    $fail = 1
}
Else { $Problem["1"]["Permission Results"] = "PASS" }


$appPools = Get-WebConfiguration -Filter '/system.applicationHost/applicationPools/add'


foreach($appPool in $appPools)
{
    if($appPool.ProcessModel.identityType -eq "SpecificUser")
    {
       if($appPool.Name -eq "SecretServer")
       {
        #Read password in from credential manager and decrypt
        $Password = Read-Host "Enter Service account Password" -AsSecureString
        $PasswordDecrypted = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        
       
        # Compare Credential Manager Password with App Pool Password
        if ($appPool.ProcessModel.Password -ceq $PasswordDecrypted) {
            
            $Problem["1"]["Password Results"] = "PASS"
            # We then get a response from the site.
            $HTTP_Response = $HTTP_Request.GetResponse()

            # We then get the HTTP code as an integer.
            $HTTP_Status = [int]$HTTP_Response.StatusCode

            If ($HTTP_Status -eq 200) { $Problem["1"]["Site reachable"] = "PASS" }
            Else {
                $Problem["1"]["Site unreachable"] = "FAIL"
                $fail = 1
            }            
        } 
        else {
            $Problem["1"]["Password Results"] = "FAIL"
            $fail =  1
            #echo $appPool.ProcessModel.Password" = "$PasswordConverted # This will display the passwords in plaintext
        }
       }
    }

}



# Finally, we clean up the http request by closing it.
If ($HTTP_Response -eq $null) { } 
Else { $HTTP_Response.Close() }

if ($fail -eq 1) { $failures.Add("Problem 1:", "FAIL") }

$fail = 0


##############################
# Begin Problem 2 Evaluation #
##############################


#
# Task #1 Either change permissions on the secret or move the secret to Breakfix2... DONE
#

$Problem["2"] = [ordered]@{}

$SecretQueryResult = Invoke("SELECT SecretName FROM dbo.TbSecret WHERE FolderID = 46 AND Active = '1'") # Should be svc_accounts

if ($SecretQueryResult -eq $null -or $SecretQueryResult -eq "" ){ # Null would be the response if it is not in Breakfix1
    
    $SecretQuery2Result = Invoke("SELECT SecretName FROM dbo.TbSecret WHERE FolderID = 47")

    if ($SecretQuery2Result -eq $null){  # Null indicates it not in Breakfix2 nor in Breakfix1
        
        else{
            $Problem["2"]["Secret not found"] = "Fail"
            $fail = 1
        }
    }
    else { $Problem["2"]["Secret moved to correct folder"] = "PASS" } # Successfully moved to Breakfix 2
        
}
Else {  # Secret still exists in Breakfix 1, so check for permissions   
   $GroupIdResult = Invoke("SELECT GroupId FROM tbFolderGroupPermission WHERE FolderId = '46'")
   if ($GroupIdResult -eq '18'){ 
         $Problem["2"]["Secret location or permission"] = "FAIL" #He's gone and should not have access
         $fail = 1
    } 
   else { $Problem["2"]["Secret location or permission"] = "PASS" } # Permissions are not assigned to Ruiz
}

if ($fail -eq 1){$failures.Add("Problem 2:", "FAIL")}
$fail = 0

##############################
# Begin Problem 3 Evaluation #
##############################
 
#
# Task #1 Verify the folder in the backup configuration exists on the filesystem... DONE
#
# Task #2 Verify a backup exists... DONE
#

$Problem["3"] = [ordered]@{}

$BackupFolder = Invoke("SELECT BackupDatabasePath FROM tbBackupConfiguration WHERE BackupConfigurationId = '1'")

if (Test-Path -Path $BackupFolder) {
    if((Get-ChildItem -Path $BackupFolder| Measure-Object).Count -eq 0) { 
        $Problem["3"]["Backup Performed"] = "Fail" 
        $fail = 1
    }
    else {

        $Problem["3"]["Backup Performed"] = "PASS"
        $BackupFiles = Get-ChildItem -Path $BackupFolder
        $Problem["3"]["Backup Files"] = $BackupFiles
    }
} 
else { 
    $Problem["3"]["Backup Performed"] = "FAIL" 
    $fail = 1
    }

if ($fail -eq 1){$failures.Add("Problem 3:", "FAIL")}
$fail = 0

##############################
# Begin Problem 4 Evaluation #
##############################

#
# Task #1 Verify password has been changed... DONE
#
# Task #2 Verify Pending Engine is activated or local site is being used for discovery... DONE
#
# Task #3 Verify Domain User Discovery1 exists... DONE
#
# Task #4 Verify Service Account svc_disc2 exists... DONE
#

$UserResult1 = Invoke("SELECT AccountName FROM tbComputerAccount WHERE AccountName = 'Discover1'")
$UserResult2 = Invoke("SELECT AccountName FROM tbComputerAccount WHERE AccountName = 'svc_disc2'")

$Problem["4"] = [ordered]@{}


$KeyUpdateResponse = Invoke("SELECT TOP 1 [Action] FROM tbAuditSecret WHERE SecretId = 2 AND [Action] = 'CHANGE PASSWORD' AND DATEDIFF(day,DateRecorded,GETDATE()) between 0 and 30")

if($KeyUpdateResponse -eq "CHANGE PASSWORD") {
    $Problem["4"]["Credentials Changed"] = "PASS"
}
else {
    $Problem["4"]["Credentials Changed"] = "FAIL"
    $fail = 1
}
 
$EngineResult = Invoke("SELECT ActivationStatus FROM tbEngine WHERE FriendlyName = 'APP.delinealabs.com'") # Check Activation of Engine

if ($EngineResult -eq 0) { 
    $SiteResult = Invoke("SELECT SiteId FROm tbDiscoverySource WHERE DiscoverySourceId = 1")
    if ($SiteResult -eq 4){
        $Problem["4"]["Engine Activated"] = "FAIL"
        $fail = 1
    }
    elseif ($SiteResult -eq 1) { $Problem["4"]["Engine Activated"] = "PASS" }
}
else { $Problem["4"]["Engine Activated"] = "PASS" }

if ($UserResult1 -eq $null) { 
    $Problem["4"]["Discover1 Found"] = "FAIL"
    $fail = 1
}
else { $Problem["4"]["Discover1 Found"] = "PASS" }

if ($UserResult2 -eq $null) { 
    $Problem["4"]["svc_disc2 Found"] = "FAIL"
    $fail = 1
}
else { $Problem["4"]["svc_disc2 Found"] = "PASS" }


if ($fail -eq 1){$failures.Add("Problem 4:", "FAIL")}
$fail = 0

##############################
# Begin Problem 5 Evaluation #
##############################



#
# Task #1 Verify request has been responded to... DONE
#

$Problem["5"] = [ordered]@{}

$RequestResult = Invoke("SELECT ResponseUserId, CONVERT(varchar, ExpirationDate,101) AS D FROM tbSecretAccessRequest WHERE RequestUserId = '17' AND SecretAccessRequestId = '9'") #AND  ExpirationDate > Convert(DateTime, '2022-03-03')")
$RequestDate = $RequestResult[1]
[DATETIME]$RequestDate
$CompareDate = "03/02/2022"
[DATETIME]$CompareDate

if ($RequestResult[0] -eq $null) {
    $Problem["5"]["Access Request"] = "FAIL"
    $fail = 1
}
else {
    if ($RequestDate -gt $CompareDate){ $Problem["5"]["Access Request"] = "PASS" }
    else {
        $Problem["5"]["Access Request"] = "FAIL" 
        $fail = 1
    }
}

if ($fail -eq 1){$failures.Add("Problem 5:", "FAIL")}
$fail = 0

##############################
# Begin Problem 6 Evaluation #
##############################



#
# Task #1 Verify new Social Media template has been created... DONE
#
# Task #2 Verify Template is validating password requirements on create... DONE
#
# Task #3 Verify Template is validating password requirements on edit... DONE
#
# Task #4 Verify Secret is using new Template. Should be ID 1053. Marketing FolderID 39 in tbSecret... DONE
#
# Task #5 Verify new Template is only template in folder restricted templates allowed list... DONE
#
# Task #6 Verify Social Media Template is applying Social Media Password Requirements on Password field... DONE


$Problem["6"] = [ordered]@{}


$TemplateResult = Invoke("SELECT SecretTypeId, ValidatePasswordRequirementsOnCreate, ValidatePasswordRequirementsOnEdit FROM tbSecretType WHERE SecretTypeName like 'Social Media%[a-z0-9]%'")


if ($TemplateResult -eq $null) { #They did not make a new template
    $TemplateQuery = Invoke("SELECT SecretTypeId, ValidatePasswordRequirementsOnCreate, ValidatePasswordRequirementsOnEdit FROM tbSecretType WHERE SecretTypeName like 'Social Media%'")
    if($TemplateQuery[1] -eq 1) {
        $Problem["6"]["Template Validates on Create"] = "PASS"
        if($TemplateQuery[2] -eq 1) { $Problem["6"]["Template Validates On Edit"] = "PASS" }
        else {
            $Problem["6"]["Template Validates On Edit"] = "FAIL"
            $fail = 1
        }
    }
    else {
            $Problem["6"]["Template Validates on Create"] = "FAIL"
            $fail = 1
    }
    $PasswordRequirements = Invoke("SELECT PasswordRequirementID FROM tbSecretField WHERE SecretTypeId = 6056")
    if ($PasswordRequirements -eq 5) { $Problem["6"]["Template using Social Media Password Requirements"] = "PASS" }
    else {
        $Problem["6"]["Template using Social Media Password Requirements"] = "FAIL"
        $fail = 1
    }
}
else {
    $Problem["6"]["New Social Media Template"] = "FOUND"
  
        if($TemplateResult[1] -eq 1) {
            $Problem["6"]["Template Validates on Create"] = "PASS"
            if($TemplateResult[2] -eq 1) {
                $Problem["6"]["Template Validates On Edit"] = "PASS"
                $SecretTypeResult = Invoke("SELECT SecretTypeID FROM tbSecret WHERE SecretID = 1053")

                if ($SecretTypeResult = 6056) { 
                    $Problem["6"]["Secret Template Changed"] = "FAIL"
                    $fail = 1
                }
                else { $Problem["6"]["Secret Template Changed"] = "PASS" }
            }
            else {
                $Problem["6"]["Template Validates On Edit"] = "FAIL"
                $fail = 1
            }
        }
        else {
            $Problem["6"]["Template Validates on Create"] = "FAIL"
            $fail = 1
        }
        $PasswordRequirements = Invoke("SELECT PasswordRequirementID FROM tbSecretField WHERE SecretTypeId =" + $TemplateResult[0])
        if ($PasswordRequirements -eq 5) { $Problem.add('6.6',"Template using Social Media Password Requirements: PASS") }
        else {
            $Problem["6"]["Template using Social Media Password Requirements"] = "FAIL"
            $fail = 1
        }
}




$AllowedListResult = Invoke("SELECT SecretTypeId FROM tbFolderToSecretType WHERE FolderId = 39")

if ($AllowedListResult -eq $null) { # Null indicates all templates are allowed
    $Problem["6"]["Allowed List Restricted to New Template"] = "FAIL"
    $fail = 1
}
else {
  $Problem["6"]["Allowed List Restricted to New Template"] = "PASS" 
}


if ($fail -eq 1){$failures.Add("Problem 6:", "FAIL")}
$fail = 0

##############################
# Begin Problem 7 Evaluation #
##############################

#
# Task #1 Verify Wade has permissions for centos.delinealabs.com\thycotic_acct Secret... DONE
#
# Task #2 Verify Proxy is enabled... DONE
#
# Task #3 Verify Terminal is enabled... DONE
#
# Task #4 Create SSH connection from Generic using putty... DONE
#

$Problem["7"] = [ordered]@{}

# Wade Hoffman's group ID: 39
# Centos Secret ID is 5

$CentosQueryResult = Invoke("SELECT GroupID FROM tbSecretACL WHERE SecretID = 5 AND GroupID = 16")
$ProxyResult = Invoke("SELECT EnableSSHProxy, EnableSSHTerminal FROM tbAdminProxyingConfiguration")

if ($CentosQueryResult -eq $null) { 
    $Problem["7"]["CentOS Permissions"] = "FAIL"
    $fail = 1
}
Else { $Problem["7"]["CentOS Permissions"] = "PASS" }

if ($ProxyResult[0] -eq $true){ $Problem["7"]["Proxy Enabled"] = "PASS" }
else { 
    $Problem["7"]["Proxy Enabled"] = "FAIL" 
    $fail = 1
}
if ($ProxyResult[1] -eq $true){ 
    $Problem["7"]["Terminal Enabled"] = "PASS"
    # The following shows a successful connection, NOT a successful command execution
    $Error.Clear()
    $b = New-PSSession generic
    $SSH = invoke-command -Session $b -Script { echo y | plink -v -ssh admin@10.0.0.2 -pw ThycoticDemo! "man cat" } 2>&1 > "$PSScriptRoot\output.txt"
    #$Error | Out-File $file -Append
    Remove-PSSession $b
    
    
}
else { 
    $Problem["7"]["Terminal Enabled"] = "FAIL"
    $fail = 1
}


if ($fail -eq 1) {$failures.Add("Problem 7:", "FAIL")}
$fail = 0

##############################
# Begin Problem 8 Evaluation #
##############################

#
# Task #1 Verify  delinealabs\svc_thy_backup password was changed and heartbeat is successful... DONE
#
# Task #2 Verify Change Password On Checkin is enabled... DONE
#
# Task #3 Check Out Secret and Check Back in
#


$Problem["8"] = [ordered]@{}

$SecretChangedResult = Invoke("SELECT TOP 1 [Action] FROM tbAuditSecret WHERE SecretId = 1034 AND [Action] = 'CHANGE PASSWORD' AND DATEDIFF(day,DateRecorded,GETDATE()) between 0 and 30")

if($SecretChangedResult -eq "CHANGE PASSWORD") { $Problem["8"]["Password Changed"] = "PASS" }
else { 
    $Problem["8"]["Password Changed"] = "FAIL" 
    $fail = 1
}

$HeartBeat_CheckIn = Invoke("SELECT LastHeartBeatStatus, CheckOutChangePassword, CheckOutEnabled FROM tbSecret WHERE SecretName LIKE '%svc_backup%'")

if ($HeartBeat_CheckIn[0] -eq 0) { 
    $Problem["8"]["HeartBeat Status"] = "FAIL" 
    $fail = 1 
}
else { $Problem["8"]["HeartBeat Status"] = "PASS" } 

if ($HeartBeat_CheckIn[2] -eq 0) { 
    $Problem["8"]["Check-Out Enabled"] = "FAIL" 
    $fail = 1
}
else { $Problem["8"]["Check-Out Enabled"] = "PASS" } 

if ($HeartBeat_CheckIn[1] -eq 0) { 
    $Problem["8"]["Check-In Change Password"] = "FAIL" 
    $fail = 1
}
else { $Problem["8"]["Check-In Change Password"] = "PASS" } 
# Task 3# See Output
if ($fail -eq 1) {$failures.Add("Problem 8:", "FAIL")}
$fail = 0

##############################
# Begin Problem 9 Evaluation #
##############################

#
# Task #1 Verify depency has a successful heartbeat:... DONE
#
# delinealabs.com\svc_require  (id: 1057)
# delinealabs.com\svc_thy_disc (id: 2)
# delinealabs.com\svc_backup   (id: 1034)
# 
# Task #2 Verify privileged account is in RPC (Role permission id 10005?)... DONE
# 
# Task #3 Verify generic credential was recently rotated... DONE
# 
# Task #4 Verify Password rotation schedule is set to every day... DONE
#
# Task #5 Verify Runs for Dependencies are successful... DONE

#ComputerDependencyID	ComputerID	DependencyName
#1167	3	SNMP
#1168	3	RLM Endpoint
#1169	3	MSAccountSync
#1170	3	LDAP Updater
#1171	3	HostService
#1172	3	GenericService

#SecretName	SecretId
#delinealabs.com\svc_thy_disc	2
#delinealabs.com\svc_backup	1034
#delinealabs.com\svc_require	1057

$Problem["9"] = [ordered]@{}

$HeartBeatQuery = Invoke("SELECT LastHeartBeatStatus FROM tbSecret WHERE SecretID IN (1057,2,1034)")


# Task 1
if ($HeartBeatQuery[2] -eq 0) { 
    $Problem["9"]["svc_require Heartbeat"] = "FAIL"
    $fail=1
}
else { $Problem["9"]["svc_require Heartbeat"] = "PASS" }

if ($HeartBeatQuery[0] -eq 0) { 
    $Problem["9"]["svc_thy_disc Heartbeat"] = "FAIL" 
    $fail=1
}
else { $Problem["9"]["svc_thy_disc Heartbeat"] = "PASS" }

if ($HeartBeatQuery[1] -eq 0) { 
    $Problem["9"]["svc_backup Heartbeat"] = "FAIL"
    $fail=1
}
else { $Problem["9"]["svc_backup Heartbeat"] = "PASS" }
# Task 2
$RPCResult = Invoke("SELECT TOP 1 ResetSecretID FROM tbSecretResetSecrets WHERE SecretId = 1007")

if ($RPCResult -eq $null) { 
    $Problem["9"]["RPC User Added"] = "FAIL"
    $fail=1
}
else { $Problem["9"]["RPC User Added"] = "PASS" }
# Task 3

$GenericRotation = Invoke("SELECT TOP 1 [Action] FROM tbAuditSecret WHERE SecretId = 1007 AND [Action] = 'CHANGE PASSWORD' AND DATEDIFF(day,DateRecorded,GETDATE()) between 0 and 30")

if ($GenericRotation -eq $null) { 
    $Problem["9"]["Generic Rotated"] = "FAIL" 
    $fail=1
}
else { $Problem["9"]["Generic Rotated"] = "PASS" }
# Task 4
$ScheduleResult = Invoke("SELECT ChangeScheduleType FROM tbSecretChangeSchedule WHERE SecretID = 1007")

if ($ScheduleResult -eq $null) { 
    $Problem["9"]["Rotation Schedule"] = "FAIL"
    $fail=1
}
else {
    if ($ScheduleResult -eq "Daily") { $Problem["9"]["Rotation Schedule"] = "PASS" }
    else { 
      $Problem["9"]["Rotation Schedule"] = "FAIL" 
      $fail=1
    }
}
# Task 5
$Runs = Invoke("SELECT SecretDependencyStatus FROM tbSecretDependency WHERE MachineName = 'generic.delinealabs.com' AND SecretId = 1007 AND Active = 1")

if ($($Runs.count) -eq 6) { $Problem["9"]["Runs Successful"] = "PASS" }
else {
    $Problem["9"]["Runs Successful"] = "FAIL"
    $fail=1
}


if ($fail -eq 1) {$failures.Add("Problem 9:", "FAIL")}
$fail = 0

###############################
# Begin Problem 10 Evaluation #
###############################

#
# Task #1 Verify account for Distributed Engine Service has correct permissions... DONE
# 
# Task #2 Verify old Engine is gone... DONE
#
# Task #3 Verify new engine is in place... DONE
#
# Task #4 Verify new engine is activated on TampDataCenter Site... DONE
#
# Task #5 Verify Discovery source scanner settings are enabled... DONE
#
# Task #6 Verify Discovery source scanner settings are set to discover application pools using svc_thy_disc... DONE
#
# Task #7 Verify application pool ThycoticAPP has been discovered... DONE
#


$Problem["10"] = [ordered]@{}


$ServiceAccount = Get-WMIObject Win32_Service -Filter "Name LIKE 'Thycotic.DistributedEngine.Service'" | Format-List StartName

if ($ServiceAccount -Contains "local") {
    $Problem["10"]["Service has correct permissions"] = "FAIL"
    $fail = 1
}
else { $Problem["10"]["Service has correct permissions"] = "PASS" }

#Join for Result
#SELECT SecretID  FROM tbDiscoveryScannerCredentialMap DSCM LEFT JOIN tbDiscoverySourceScannerMap DSSM ON DSSM.DiscoverySourceScannerMapId = DSCM.DiscoverySourceScannerMapId  WHERE DSSM.DiscoverySourceId = 1 AND DSSM.DiscoveryScannerId = 6 AND DSSM.DiscoveryScanTypeId = 4 AND DSSM.DiscoveryItemScannerId = 4

$AppPoolScanResult = Invoke("SELECT DiscoverySourceScannerMapId FROM tbDiscoverySourceScannerMap WHERE DiscoverySourceId = 1 AND DiscoveryScannerId = 6 AND DiscoveryScanTypeId = 4 AND DiscoveryItemScannerId = 4")
$CredResult = Invoke("SELECT SecretId FROM tbDiscoveryScannerCredentialMap WHERE DiscoverySourceScannerMapId = $AppPoolScanResult")

if ($AppPoolScanResult -eq $null) {
    $Problem["10"]["Application Pool Scanner Exists"] = "FAIL"
    $fail = 1
}
else { $Problem["10"]["Application Pool Scanner Exists"] = "PASS"}

if ($CredResult -eq 2) { $Problem["10"]["Application Pool has correct Credentials"] = "PASS" }
else {
    $Problem["10"]["Application Pool has correct Credentials"] = "FAIL"
    $fail = 1
}

$EngineResult = Invoke("SELECT EngineId FROM tbEngine WHERE [Version] LIKE '%7.89%' AND ActivationStatus = 1 AND ActivatedBy = 2 AND SiteID = 4")

if ($EngineResult -eq $null) {
    $Problem["10"]["New Engine Activated on Tampa Site"] = "FAIL"
    $fail = 1
}
else { $Problem["10"]["New Engine Activated on Tampa Site"] = "PASS" }

$OldEngineResult = Invoke("SELECT EngineId FROM tbEngine WHERE Version = 7.89 AND ActivationStatus = 1 AND ActivatedBy = 2 AND SiteID IS NULL")

if ($OldEngineResult -eq $null) { $Problem["10"]["Old Engine Deactivated"] = "PASS" }
else {
    $Problem["10"]["Old Engine Deactivated"] = "FAIL" 
    $fail = 1
}


$DiscoverSourceResult = Invoke("SELECT DiscoverySourceScannerMapId FROM tbDiscoverySourceScannerMap WHERE DiscoveryItemScannerId = 4")
 
$AppPool = Invoke("SELECT SecretId FROM tbDiscoveryScannerCredentialMap WHERE DiscoverySourceScannerMapId = $DiscoverSourceResult")

if ($DiscoverSourceResult -eq $null) {
    $Problem["10"]["Discovery Source Scanner Item"] = "FAIL" 
    $fail = 1    
}
else { 
    $Problem["10"]["Discovery Source Scanner Item"] = "PASS" 
    if ($AppPool -eq 2) { $Problem["10"]["Discovery Source Correct Credential"] = "PASS" }
    else {
        $Problem["10"]["Discovery Source Correct Credential"] = "FAIL"
        $fail = 1
    }
}




$WebSecretResult = Invoke("SELECT ComputerAccountId FROM tbComputerAccount where AccountName LIKE '%svc_web%'")

if ($WebSecretResult -eq $null) {
    $Problem["10"]["svc_webservers Exists"] = "FAIL" 
    $fail = 1
}
else { $Problem["10"]["svc_webservers Exists"] = "PASS" }

if ($fail -eq 1) {$failures.Add("Problem 10:", "FAIL")}
$fail = 0

###############################
# Begin Problem 11 Evaluation #
###############################



#
# Task #1 Verify an engine is installed on Generic... DONE
#
# Task #2 Verify engine is assigned to WashingtonDC... DONE
#
# Task #3 Verify Siteconnector is a working siteconnector... DONE
#
# Task #4 Verify Site connector is validated... DONE
#
# Task #5 Verify distribute engine is validated... DONE

$Problem["11"] = [ordered]@{}

$ConnectorResult = Invoke("SELECT SiteConnectorId FROM tbSite WHERE SiteId = 3")
$EngineID = Invoke("SELECT EngineId FROM tbEngineSettings WHERE SiteId = 3")
$EngineInstalled = Get-WmiObject -Class Win32_Product -ComputerName generic -filter "Name LIKE '%Distributed%'" | select Name

# Task 1
if ($EngineInstalled -eq $null) { 
    $Problem["11"]["Engine Installed"] = "FAIL" 
    $fail=1
}
else { $Problem["11"]["Engine Installed"] = "PASS" }

# Task 2
if ($EngineID -eq $null) { 
    $Problem["11"]["Engine Assigned"] = "FAIL" 
    $fail=1
}
else { $Problem["11"]["Engine Assigned"] = "PASS" }

# Task 3
if ($ConnectorResult -eq 2) { $Problem["11"]["Working Site Connector"] = "PASS" }
else {     $Problem["11"]["Working Site Connector"] = "FAIL"
    $fail=1 }
# Task 4

$SiteValidation = Invoke("SELECT EngineLogId FROM tbEngineLog EL LEFT JOIN tbEngine E ON E.EngineId = EL.EngineId WHERE E.FriendlyName = 'generic.delinealabs.com' AND EL.Message LIKE '%Received%request%success%'")
if ($SiteValidation -eq $null) {
    $Problem["11"]["Site Validation"] = "FAIL"
    $fail=1
}
else { $Problem["11"]["Site Validation"] = "PASS" }

# Task 5

$EngineStatus = Invoke("SELECT ConnectionStatus, ActivationStatus FROM tbEngine WHERE FriendlyName = 'generic.delinealabs.com' AND SiteId IS NOT NULL")

if ($EngineStatus -eq $null) {
    $Problem["11"]["Generic Engine Activated"] = "FAIL"
    $fail=1
}
else {
    if ($EngineStatus[0] -eq 1) {
        $Problem["11"]["Generic Engine Connected"] = "PASS"
        if ($EngineStatus[1] -eq 1) { $Problem["11"]["Generic Engine Activated"] = "PASS" } 
        else {
            $Problem["11"]["Generic Engine Activated"] = "FAIL"
            $fail=1
        }

    }
    else {
        $Problem["11"]["Generic Engine Connected"] = "FAIL"
    }
}
if ($fail -eq 1) {$failures.Add("Problem 11:", "FAIL")}
$fail = 0

###############################
# Begin Problem 12 Evaluation #
###############################


#
# Task #1 Verify Secret template for Delinealabs\svc_require is set to save history of last 5 changes (id: 6059)... DONE
#
# Task #2 Verify Password has been changed at least 5 times... DONE
#

$Problem["12"] = [ordered]@{}

$HistoryResult = Invoke("SELECT HistoryLength FROM tbSecretField WHERE SecretTypeID = 6059 AND SecretFieldId = 350")

if ($HistoryResult -ge 5) { $Problem["12"]["History Changed"] = "PASS" }
else { 
    $Problem["12"]["History Changed"] = "FAIL"
    $fail=1
}


$PasswordChanged5 = Invoke("SELECT COUNT([Action]) FROM tbAuditSecret WHERE SecretId = 1057 AND [Action] = 'CHANGE PASSWORD' AND DATEDIFF(day,DateRecorded,GETDATE()) between -1 and 30")

if ($PasswordChanged5 -ge 5) { $Problem["12"]["Password Changed 5 times"] = "PASS" }
else { 
    $Problem["12"]["Password Changed 5 times"] = "FAIL"
    $fail=1
}

if ($fail -eq 1) {$failures.Add("Problem 12:", "FAIL")}
$fail = 0

###############################
# Begin Problem 13 Evaluation #
###############################


#
# Task #1 Verify Session recording is enabled for generic.delinealabs.com\Administrator Secret (id: 1009)... DONE
#
# Task #2 Verify ASR is onstalled on Generic... DONE
#
# Task #3 Verify session exists for secret... DONE 
#

$Problem["13"] = [ordered]@{}

$ConfigResult = Invoke("SELECT EnableSessionRecording FROM tbConfiguration")
$SessionResult = Invoke("SELECT IsSessionRecordingEnabled FROM tbSecret WHERE SecretId = 1009")

if ($ConfigResult -eq 0 ) { 
    $Problem["13"]["Session Recording Enabled"] = "FAIL" 
    $fail=1
}
else {
    if ($SessionResult -eq 0) { 
        $Problem["13"]["Session Recording Enabled"] = "FAIL" 
        $fail=1
    }
    else { $Problem["13"]["Session Recording Enabled"] = "PASS" }
}

$ASRInstalled = Get-WmiObject -Class Win32_Product -ComputerName generic -filter "Name LIKE '%Session%'" | select Name

if ($ASRInstalled -eq $null) { 
    $Problem["13"]["Advanced Session Recording Installed"] = "FAIL"
    $fail=1
}
else { $Problem["13"]["Advanced Session Recording Installed"] = "PASS" }

$SessionExists = Invoke("SELECT SecretSessionID FROM tbSecretSession WHERE SecretId = 1009 AND DATEDIFF(day,StartDate,GETDATE()) between -1 and 30")

if ($SessionExists -eq $null) {
    $Problem["13"]["Session Exists"] = "FAIL"
    $fail=1
} 
else { $Problem["13"]["Session Exists"] = "PASS" }

if ($fail -eq 1) {$failures.Add("Problem 13:", "FAIL")}
$fail = 0

###############################
# Begin Problem 14 Evaluation #
###############################


#
# Task #1 Output Powershell.ps1 Results... DONE
#

(gc $PSScriptRoot\powershell.ps1) | Foreach-Object {
$_ -replace '^*Write-Host', 'Write-Output' `
-replace '^*Write-Output.*', "`$0 >> $file" `
-replace 'Read-Host -Prompt', "" `
-replace "Enter search string: ", "generic"} | sc $PSScriptRoot\powershell2.ps1

#####################
# Begin File Output #
#####################

echo $student" - "$date | Tee-Object -FilePath $file #Skip EchoOut to create a new file
EchoOut("")

if ($failures.Count -eq 0) { EchoOut("Overall Evaluation: PASS `n") }
else {
    EchoOut("Overall Evaluation: FAIL `n")
    EchoOut("Problems Failed `r====================")
    EchoOut($failures | Format-Table -HideTableHeaders )
}



#foreach ($h in $Problem.GetEnumerator() )
#{    
 #   echoOut "Break-Fix Problem #$($h.Name) `r====================="
 #   echoOut "$($h.Value)"
   
#}

for ($i=1; $i -le 7; $i++) {
    echoOut("Break-Fix Problem #$i `r=====================")
    EchoOut($Problem["$i"] | Format-Table -HideTableHeaders )
    echoOut("`n")
}EchoOut("SSH Results `r=====================")
EchoOut(Get-Content "$PSScriptRoot\output.txt" -Raw)
#Remove-Item "$PSScriptRoot\output.txt"
EchoOut("Break-Fix Problem #8 `r=====================")

EchoOut($Problem["8"] | Format-Table -HideTableHeaders )

try
{

    $api = "https://app.delinealabs.com/SecretServer/api/v1"
    $tokenRoute = "https://app.delinealabs.com//SecretServer/oauth2/token";

    $creds = @{
        username = "admin"
        password = "ThycoticDemo!"
        grant_type = "password"
    }        

    $token = ""
    $response = Invoke-RestMethod $tokenRoute -Method Post -Body $creds
    $token = $response.access_token;    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $token")

    $secretId = 1034
    #SecretArgs are only required as needed for the REST endpoint. ForceCheckIn may be relevant if the secret has been checked out by another user since you will need to force checkin to use the secret. This removes the other user's checkin and rotates the password if the secret is configured to do so.
    $secretArgs = @{
        #DoubleLockPassword
        #TicketNumber
        #TicketSystemId
        #Comment ="Passing a comment"
        #ForceCheckIn = $false
        #ExposeFieldValues
        #IncludeInactive
    }| ConvertTo-Json

    $secret = Invoke-RestMethod $api"/secrets/$secretId/check-out" -Method Post -Body $secretArgs -Headers $headers -ContentType "application/json"
    

    EchoOut($secret)
    EchoOut($secret[0].message)
    EchoOut($secret[0].code)

    EchoOut("Name: " + $secret.name)
    EchoOut("Active: " + $secret.active)
    EchoOut("Template: " + $secret.secretTemplateName)
    EchoOut("Heartbeat Status: " + $secret.lastHeartBeatStatus)
    EchoOut("RPC: " + $secret.lastPasswordChangeAttempt)
    EchoOut("Checkout: " + $secret.CheckedOut)
    EchoOut("Checkout User: " + $secret.CheckOutUserDisplayName)    
    
    $secret = Invoke-RestMethod $api"/secrets/$secretId/check-in" -Method Post -Body $secretArgs -Headers $headers -ContentType "application/json"    
    EchoOut($secret)
    EchoOut($secret[0].message)
    EchoOut($secret[0].code)

    EchoOut("Name: " + $secret.name)
    EchoOut("Active: " + $secret.active)
    EchoOut("Template: " + $secret.secretTemplateName)
    EchoOut("Heartbeat Status: " + $secret.lastHeartBeatStatus)
    EchoOut("RPC: " + $secret.lastPasswordChangeAttempt)
    EchoOut("Checkout: " + $secret.CheckedOut)
    EchoOut("Checkout User: " + $secret.CheckOutUserDisplayName)}catch [System.Net.WebException]
{
    EchoOut("----- Exception -----")
    EchoOut($_.Exception)
    EchoOut($_.Exception.Response.StatusCode)
    EchoOut($_.Exception.Response.StatusDescription)
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
    EchoOut($responseBody.errorCode + " - " + $responseBody.message)
    foreach($modelState in $responseBody.modelState)
    {
        $modelState
    }
}


Echoout("`n")


for ($i=9; $i -le 13; $i++) {
    echoOut "Break-Fix Problem #$i `r====================="
    EchoOut($Problem["$i"] | Format-Table -HideTableHeaders )
    echoOut("`n")
}


EchoOut("Break-Fix Problem #14 `r=====================")

& $PSScriptRoot\powershell2.ps1
