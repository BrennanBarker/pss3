async function sha256Hash(msg) {
    const encoder = new TextEncoder();
    return await window.crypto.subtle.digest("SHA-256", encoder.encode(msg));
}

async function hmacSha256(key, msg) {
    const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return crypto.subtle.sign("HMAC", k, msg)
}

async function awsSigV4(secretAccessKey, date, region, stringToSign) {
    const encoder = new TextEncoder()
    key = encoder.encode("AWS4" + secretAccessKey)
    const msgs = [date, region, "s3", "aws4_request", stringToSign]
    for (const msg of msgs.map((x) => encoder.encode(x))) { 
        key = await hmacSha256(key, msg) 
    }
    return hex(key);
}

const hex = (ab) => new Uint8Array(ab).reduce((x,y) => x += y.toString(16).padStart(2, '0'), '')

async function s3GetObjectPresignedUrl(bucket, key, region, awsAccessKeyId, awsSecretAccessKey, datetime = new Date(), expiration = 86400) {
    const amzdate = datetime.toISOString().replaceAll('-', '').replaceAll(':', '').split('.')[0]+'Z'
    const date = amzdate.split('T')[0]
    const credentialScope = `${date}/${region}/s3/aws4_request`
    const credential = `${awsAccessKeyId}/${credentialScope}`.replaceAll("/", "%2F")
    const canonicalQueryString = `X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${credential}&X-Amz-Date=${amzdate}&X-Amz-Expires=${expiration}&X-Amz-SignedHeaders=host`
    const canonicalRequest = `GET\n/${key}\n${canonicalQueryString}\nhost:${bucket}.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD`
    const canonicalRequestHash = hex(await sha256Hash(canonicalRequest))
    const stringToSign = `AWS4-HMAC-SHA256\n${amzdate}\n${credentialScope}\n${canonicalRequestHash}`
    const signature = await awsSigV4(awsSecretAccessKey, date, region, stringToSign)
    return `https://${bucket}.s3.amazonaws.com/${key}?${canonicalQueryString}&X-Amz-Signature=${signature}`
}

document.head.innerHTML = ''
document.body.innerHTML = '<input type="file" id="config-file" />'
document.querySelector('#config-file').addEventListener('change', function(event) {
    const reader = new FileReader();
    reader.onload = async function (e) {
        const fileContent = e.target.result;
        const config = Object.fromEntries(fileContent.split('\n').map(line => line.split('=')).filter(([x,y])=>x.length > 0))
        const bucket = window.location.host.replace('.s3.amazonaws.com','')
        document.body.innerHTML = ''
        for (let key of config.keys.split(',')) {
            key = key.trim()
            const href = await s3GetObjectPresignedUrl(bucket, key, config.AWS_REGION, config.AWS_ACCESS_KEY, config.AWS_SECRET_ACCESS_KEY)
            const link = document.createElement('a')
            link.setAttribute('href', href)
            link.textContent = key
            document.body.innerHTML += link.outerHTML+'<br />'
        }
    };
    reader.readAsText(event.target.files[0]);
});