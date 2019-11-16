[CmdletBinding()]
Param(
    [ValidateSet("AU","BR","CA","CH","DE","DK","ES","FI","FR","GB","IE","IR","NO","NL","NZ","TR","US")]
        [ARRAY]$Country = "US",
    [ValidateSet("Male","Female")]
        [STRING]$Gender = "Male",
    [ValidateRange(1,2500)] 
        [INT]$Results
)

Import-Module -Name 'ActiveDirectory' -Force -NoClobber -ErrorAction Stop
$Domain = Get-ADDomain -Current LocalComputer
$DomainDN = $Domain.DistinguishedName
$DomainPDC = $Domain.PDCEmulator
$TargetOUName = "OU=USERS,OU=CORP,$DomainDN"
$UPN  = "corp.domain.com"

[STRING]$WebRequestarameters = $null
foreach($ScriptParameters in $PSBoundParameters.Keys){
    Switch($ScriptParameters){
        'Country' { $WebRequestarameters += "&nat=$(($Country -join ",").ToLower())"   }
        'Gender' { $WebRequestarameters += "&gender=$($Gender.ToLower())" }
        'Results' { $WebRequestarameters += "&results=$Results" }
    }
}

[STRING]$PasswordParameters = "upper,lower,number,16"
$WebRequestURL = "https://randomuser.me/api/?format=PrettyJSON$WebRequestarameters&password=$PasswordParameters&exc=email,registered,dob&noinfo"
$WebData = Invoke-WebRequest $WebRequestURL -UseBasicParsing | ConvertFrom-Json
$TextInfo = (Get-Culture).TextInfo

Foreach($User in $WebData.results ){
    $GivenName = $TextInfo.ToTitleCase($user.name.first)
    $Surname = $TextInfo.ToTitleCase($user.name.Last)
    $ADUserObj = @{
        'Description' = "Demo user"

        'Name' = "$GivenName $Surname"
        'DisplayName' = "$GivenName $Surname"
        'GivenName' = $GivenName
        'Surname' = $Surname
        
        'StreetAddress' = "$($User.location.street.Number) $($User.location.street.Name)"
        'City' = $TextInfo.ToTitleCase($User.location.city)
        'PostalCode' = $User.location.postcode
        'State' = $TextInfo.ToTitleCase($User.location.state)
        'Country' = $User.Nat

        'MobilePhone' = $User.cell
        'OfficePhone' = $User.phone

        'UserPrincipalName' = "$(("$GivenName.$Surname").Tolower())@$UPN"
        'SamAccountName' = ("$GivenName.$Surname").Tolower()
        'EmployeeID' = $(Get-Random -Minimum 0 -Maximum 9999).ToString('00000')
        'AccountPassword' = (ConvertTo-SecureString -String "#$($user.login.password)!" -AsPlainText -Force)
        'Enabled' = $True
        'PasswordNeverExpires' = $true
    }

    New-ADUser @ADUserObj -Path $TargetOUName -Server $DomainPDC -ErrorAction SilentlyContinue
    Invoke-WebRequest $User.picture.large -OutFile .\tmp.jpg
    Set-ADUser $ADUserObj["SamAccountName"] -Replace @{thumbnailPhoto=([byte[]](Get-Content .\tmp.jpg -Encoding byte))}
}

Remove-Item .\tmp.jpg -Force
