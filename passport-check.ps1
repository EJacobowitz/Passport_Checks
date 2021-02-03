
. C:\bat\function\PSTools.ps1


$query1 = 'select Emplno, Ordering, Passport_Number, Passport_Country, Passport_ExpireDate, Passport_OID, Passport_IssuePlace, Updateid_Updempno, Updateid_Upddate from EP where passport_expiredate < 20000101;'
$results = Get-odbcdata -DSN crewdata -query $query1
if ($null -ne $results) {
    foreach ($record in $results) {
        $newdate = "20" + $record.Passport_ExpireDate.Substring(2, 6)
        $current_exdate = $record.Passport_ExpireDate.ToString()
        $employeenum = $record.Emplno.ToString()
        $updateid = $record.Updateid_Updempno.ToString()
        $updatedt = $record.Updateid_Upddate.tostring()
        $query2 = "update EP set Passport_ExpireDate = $newdate where Emplno = $employeenum"
        Get-odbcdata -DSN crewdata -query $query2
        $message = "$($employeenum) had wrong passport expiration date of $($current_exdate) and was changed to $($newdate). The last person to update the crewmember was $($updateid) on $($updatedt)."
        write-customlog -eventlogname Application -EventSource "Crewtrac-Passport" -EventMessage $message -EventNum 9991
    }
}

#Create Expired passport list
$today = (get-date -Format yyyyMMdd).ToString()
$query3 = "select EM.Emplno, concat(concat(rtrim(EM.emplname_Lname), ', '), rtrim(EM.emplname_Fname)) as name, EM.Status, EP.passport_number, EP.Passport_ExpireDate, EP.Passport_OID, EP.Updateid_Updempno, EP.Updateid_Upddate from EM, EP where EM.Emplno = EP.Emplno and EM.status <> 'I' and EP.Passport_ExpireDate < '$($today)';"
$PEresults = Get-odbcdata -DSN crewdata -query $query3
if ($null -ne $PEresults) {
    $data = $PEresults | Select-Object -Property Emplno, name, Status, Passport_Number, Passport_ExpireDate, Passport_OID, Updateid_Updempno, Updateid_Upddate  | ConvertTo-Html -Fragment
    $Report = @"
    <b><p style="font-size:50px">Crewtrac Expired Passport</p></b><br>
    $($data)
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

    ConvertTo-Html -Body $Report -Title "Crewtrac Expired Passport" -Head $Header | Out-File c:\bat\CTEXPassport.html -Force
}