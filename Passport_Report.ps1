#Get Crewtrac passport events
$Yesterday = get-date -Day ((get-date).AddDays(-1)).Day -Hour 00 -Minute 00 -Second 00
$Yesterday_end = get-date -Day ((get-date).AddDays(-1)).Day -Hour 23 -Minute 49 -Second 59

$Yevents = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{
    Logname      = 'Application'
    ProviderName = 'Crewtrac-Passport'
    StartTime    = $Yesterday
    Endtime      = $Yesterday_end
} | Select-Object -Property Message, ID, ProviderName, TimeCreated

if ($null -ne $Yevents) {
    $message1 = $Yevents | ConvertTo-Html -Fragment

    $Report = @"
    <b><p style="font-size:50px">Crewtrac Passport changes</p></b><br>
    $($message1)
"@


    $Header = @"
    <style>
    table {
    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
    border-collapse: collapse;
    width: 100%;
    }
    th {
    padding-top: 12px;
    padding-bottom: 12px;
    text-align: left;
    background-color: #4d79ff;
    color: white;
    }
    </style>
"@

    ConvertTo-Html -Body $Report -Title "Crewtrac Passport changes" -Head $Header | Out-File c:\bat\CTPassport.html -Force
    $emailbody = Get-Content c:\bat\CTPassport.html -Raw
    Send-MailMessage -SmtpServer Mail.jetblue.com -from "ITSysOpsAlert@Jetblue.com" -To "EJacobowitz@Jetblue.com" -Subject "Crewtrac Passport changes" -Body $emailbody -BodyAsHtml 

}

