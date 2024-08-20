function Hex {
    param ([byte[]]$bytes)
    return [BitConverter]::ToString($bytes).Replace('-','').ToLower()
}
function SHA256Hash {
    param ([string]$data)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    return $sha256.ComputeHash($bytes)
}
function HMAC_SHA256 {
    param ([byte[]]$key, [string]$data)
    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha256.Key = $key
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    return $hmacsha256.ComputeHash($bytes)
}

function AWSSigV4 {
    param ([string]$stringToSign, [string]$secretKey, [string]$date, [string]$region)
    $kSecretKey = [System.Text.Encoding]::UTF8.GetBytes("AWS4$secretKey")
    $kDate = HMAC_SHA256 $kSecretKey $date
    $kRegion = HMAC_SHA256 $kDate $region 
    $kService = HMAC_SHA256 $kRegion "s3" 
    $kSigning = HMAC_SHA256 $kService "aws4_request" 
    return Hex (HMAC_SHA256 $kSigning $stringToSign)
}

function Get-S3GetObjectPresignedUrl {
    param (
        [string]$bucketName,
        [string]$fileKey,
        [string]$region = $env:AWS_REGION, 
        [string]$accessKey = $env:AWS_ACCESS_KEY,
        [string]$secretKey = $env:AWS_SECRET_ACCESS_KEY,
        [datetime]$datetime = (Get-Date).ToUniversalTime(),
        [Int32]$expiration = 86400
    )
    $amzdate = $datetime.ToString("yyyyMMddTHHmmssZ")
    $date = $datetime.ToString("yyyyMMdd")
    $credential = "$accessKey/$date/$region/s3/aws4_request" -replace "/", "%2F"
    $canonicalQueryString = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=$credential&X-Amz-Date=$amzdate&X-Amz-Expires=$expiration&X-Amz-SignedHeaders=host"
    $canonicalRequest = "GET`n/$fileKey`n$canonicalQuerystring`nhost:$bucketName.s3.amazonaws.com`n`nhost`nUNSIGNED-PAYLOAD"
    $canonicalRequestHash = Hex (SHA256Hash $canonicalRequest)
    $credentialScope = "$date/$region/s3/aws4_request"
    $stringToSign = "AWS4-HMAC-SHA256`n$amzdate`n$credentialScope`n$canonicalRequestHash"
    $signature = AWSSigV4 $stringToSign $secretKey $date $region
    return "https://$bucketName.s3.amazonaws.com/${fileKey}?$canonicalQueryString&X-Amz-Signature=$signature"
}

function S3DownloadObject {
    param (
        [string]$bucketName,
        [string]$fileKey,
        [string]$localPath,
        [string]$region = $env:AWS_REGION, 
        [string]$accessKey = $env:AWS_ACCESS_KEY,
        [string]$secretKey = $env:AWS_SECRET_ACCESS_KEY
    )
    $datetime = (Get-Date).ToUniversalTime()
    $amzdate = $datetime.ToString("yyyyMMddTHHmmssZ")
    $date = $datetime.ToString("yyyyMMdd")
    $scope = "$date/$region/s3/aws4_request"
    $emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $canonicalHeaders = "host:$bucketName.s3.amazonaws.com`nx-amz-content-sha256:$emptyHash`n`x-amz-date:$amzdate`n"
    $signedHeaders = "host;x-amz-content-sha256;x-amz-date"
    $canonicalRequest = "GET`n/$fileKey`n`n$canonicalHeaders`n$signedHeaders`n$emptyHash"
    $canonicalRequestHash = Hex (SHA256Hash $canonicalRequest)
    $stringToSign = "AWS4-HMAC-SHA256`n$amzdate`n$scope`n$canonicalRequestHash"
    $signature = AWSSigV4 $stringToSign $secretKey $date $region
    
    Invoke-WebRequest "https://$bucketName.s3.amazonaws.com/$fileKey" -Headers @{
        "x-amz-date" = $amzdate
        "Authorization" = "AWS4-HMAC-SHA256 Credential=$accessKey/$scope,SignedHeaders=$signedHeaders,Signature=$signature"
        "x-amz-content-sha256" = $emptyHash
    } -OutFile $localPath -SkipHeaderValidation
}

# Tests
$testBucket = "examplebucket"
$testObject = "test.txt"
$testRegion = "us-east-1"
$testAccessKey = "AKIAIOSFODNN7EXAMPLE"
$testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

$presignedUrl = Get-S3GetObjectPresignedUrl $testBucket $testObject $testRegion $testAccessKey $testSecretKey (Get-Date "24 May 2013").ToUniversalTime()
$testPresignedUrl = "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
if ($presignedUrl -ne $testPresignedUrl) {
    Write-Output "TEST FAIL: The presigned urls are not equal."
    Write-Output $presignedUrl
    Write-Output $testPresignedUrl
    exit 1
}

### MAIN ###
# Load environment variables
get-content .env | ForEach-Object {
    $name, $value = $_.split('=')
    set-content env:\$name $value
}

# Rock and Roll
$fileKeys = @(
    "metadata.json"
)
$localFilePath = "/workspaces/pss3" 
foreach ($fileKey in $fileKeys) {
    S3DownloadObject $env:S3_BUCKET $fileKey $localFilePath 
}