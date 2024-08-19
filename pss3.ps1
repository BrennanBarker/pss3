# User-defined variables
$bucketName = "examplebucket"
$fileKey = "test.txt"
$localPath = "./"
$region = $env:AWS_REGION
$accessKey = $env:AWS_ACCESS_KEY
$secretKey = $env:AWS_SECRET_ACCESS_KEY

$datetime = (Get-Date).ToUniversalTime()
# $amzdate = $datetime.ToString("yyyyMMddTHHmmssZ")
$amzdate = "20130524T000000Z"
# $date = $datetime.ToString("yyyyMMdd")
$date = "20130524"

# Derived variables
$service = "s3"
$algorithm = "AWS4-HMAC-SHA256"
$credential = "$accessKey/$date/$region/$service/aws4_request" -replace "/", "%2F"
$expires = 86400
$signedHeaders = "host"
$canonicalQueryString = "X-Amz-Algorithm=$algorithm&X-Amz-Credential=$credential&X-Amz-Date=$amzdate&X-Amz-Expires=$expires&X-Amz-SignedHeaders=$signedHeaders"

# Step 1: Create canonical request
$canonicalUri = "/$fileKey"
$canonicalHeaders = "host:$bucketName.s3.amazonaws.com`n"
$payloadHash = "UNSIGNED-PAYLOAD"
$canonicalRequest = "GET`n$canonicalUri`n$canonicalQuerystring`n$canonicalHeaders`n$signedHeaders`n$payloadHash"

function Hex {
    param ([byte[]]$bytes)
    return [BitConverter]::ToString($bytes).Replace('-','').ToLower()
}
# # Step 2: Create the string to sign
function SHA256Hash {
    param ([string]$data)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    return $sha256.ComputeHash($bytes)
}
$canonicalRequestHash = Hex (SHA256Hash $canonicalRequest)
$credentialScope = "$date/$region/$service/aws4_request"
$stringToSign = "$algorithm`n$amzdate`n$credentialScope`n$canonicalRequestHash"

# Step 3: Calculate the signature
function HMAC-SHA256 {
    param (
        [byte[]]$key,
        [string]$data
    )
    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha256.Key = $key
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    return $hmacsha256.ComputeHash($bytes)
}

$kSecretKey = [System.Text.Encoding]::UTF8.GetBytes("AWS4$secretKey")
$kDate = HMAC-SHA256 $kSecretKey $date
$kRegion = HMAC-SHA256 $kDate $region 
$kService = HMAC-SHA256 $kRegion $service 
$kSigning = HMAC-SHA256 $kService "aws4_request" 
$signature = Hex (HMAC-SHA256 $kSigning $stringToSign)

$presignedUrl = "https://$bucketName.s3.amazonaws.com/${fileKey}?$canonicalQueryString&X-Amz-Signature=$signature"

# Tests

$testCanonicalRequest = @"
GET
/test.txt
X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
host:examplebucket.s3.amazonaws.com

host
UNSIGNED-PAYLOAD
"@

if ($canonicalRequest -eq $testCanonicalRequest) {
    Write-Output "PASS: The canonical requests are equal."
} else {
    Write-Output "FAIL: The canonical requests are not equal."
}

$testStringToSign = @"
AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04
"@

if ($stringToSign -eq $testStringToSign) {
    Write-Output "PASS: The stringToSigns are equal."
} else {
    Write-Output "FAIL: The stringToSigns are not equal."
}

$testSignature = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
if ($signature -eq $testSignature) {
    Write-Output "PASS: The signatures are equal."
} else {
    Write-Output "FAIL: The signatures are not equal."
    Write-Output $signature
    Write-Output $testSignature
}

$testPresignedUrl = "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
if ($presignedUrl -eq $testPresignedUrl) {
    Write-Output "PASS: The presigned urls are equal."
} else {
    Write-Output "FAIL: The presigned urls are not equal."
    Write-Output $presignedUrl
    Write-Output $testPresignedUrl
}
