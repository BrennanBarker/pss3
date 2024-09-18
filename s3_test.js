const test = {
    bucket: "examplebucket",
    key: "test.txt",
    awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
    awsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
    date: "20130524",
    datetime: new Date('24 May 2013 00:00:00Z'),
    stringToSign: "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04"
}

const test_signature = await awsSigV4(test.awsSecretAccessKey, test.date, test.region, test.stringToSign)
const true_test_signature = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
if (test_signature != true_test_signature) {
    console.error('FAIL: signatures not equal')
    console.log(test_signature, true_test_signature)
}

const test_url = await s3GetObjectPresignedUrl(test.bucket, test.key, test.region, test.awsAccessKeyId, test.awsSecretAccessKey, test.datetime)
const true_test_url = "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
if (test_url != true_test_url) {
    console.error('FAIL: urls not equal')
    console.log(test_url, true_test_url)
}
