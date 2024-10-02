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

function getSignedHeaders(canonicalHeaders) {
    return canonicalHeaders.split('\n').filter(x=>x!='').map(x=>x.split(':')[0]).join(';')
}

// payloadHash
// canonicalHeaders(host, payloadHash, amzdate)-- switch on payloadHash
// canonicalQueryString

// Just go by type?
// key
function s3Signature(region, awsAccessKeyId, bucket, payload = 'UNSIGNED-PAYLOAD') {
    const algorithm = 'AWS4-HMAC-SHA256'
    const amzdate = (new Date()).toISOString().replaceAll('-', '').replaceAll(':', '').split('.')[0]+'Z'
    const date = amzdate.split('T')[0]
    const credentialScope = `${date}/${region}/s3/aws4_request`
    const credential = `${awsAccessKeyId}/${credentialScope}`
    const host = `${bucket}.s3.amazonaws.com`
    if (payload == 'UNSIGNED-PAYLOAD') {
        const payloadHash = payload

    }

    return { signature, credential, signedHeaders, canonicalQueryString }
}



async function s3GetObjectPresignedUrl(bucket, key, region, awsAccessKeyId, awsSecretAccessKey, datetime = new Date(), expiration = 86400) {
    const algorithm = 'AWS4-HMAC-SHA256'
    const amzdate = datetime.toISOString().replaceAll('-', '').replaceAll(':', '').split('.')[0]+'Z'
    const date = amzdate.split('T')[0]
    const credentialScope = `${date}/${region}/s3/aws4_request`
    const credential = `${awsAccessKeyId}/${credentialScope}`
    const payloadHash = 'UNSIGNED-PAYLOAD'
    const host = `${bucket}.s3.amazonaws.com`
    const canonicalHeaders = `host:${host}\n`
    const signedHeaders = getSignedHeaders(canonicalHeaders)
    const canonicalQueryString = `X-Amz-Algorithm=${algorithm}&X-Amz-Credential=${credential.replaceAll("/", "%2F")}&X-Amz-Date=${amzdate}&X-Amz-Expires=${expiration}&X-Amz-SignedHeaders=${signedHeaders}`
    const canonicalUri = `/${key}`
    const canonicalRequest = `GET\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`
    const canonicalRequestHash = hex(await sha256Hash(canonicalRequest))
    const stringToSign = `${algorithm}\n${amzdate}\n${credentialScope}\n${canonicalRequestHash}`
    const signature = await awsSigV4(awsSecretAccessKey, date, region, stringToSign)
    return `https://${bucket}.s3.amazonaws.com/${key}?${canonicalQueryString}&X-Amz-Signature=${signature}`
}

async function s3ListObjects(bucket, region, awsAccessKeyId, awsSecretAccessKey, datetime = new Date()) {
    const algorithm = 'AWS4-HMAC-SHA256'
    const amzdate = datetime.toISOString().replaceAll('-', '').replaceAll(':', '').split('.')[0]+'Z'
    const date = amzdate.split('T')[0]
    const credentialScope = `${date}/${region}/s3/aws4_request`
    const credential = `${awsAccessKeyId}/${credentialScope}`
    const payloadHash = hex(await sha256Hash(''));
    const host = `${bucket}.s3.amazonaws.com`
    const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzdate}\n`;
    const signedHeaders = getSignedHeaders(canonicalHeaders)
    const canonicalQueryString = 'list-type=2';
    const canonicalUri = '/'
    const canonicalRequest = `GET\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`
    const canonicalRequestHash = hex(await sha256Hash(canonicalRequest))
    const stringToSign = `${algorithm}\n${amzdate}\n${credentialScope}\n${canonicalRequestHash}`;
    const signature = await awsSigV4(awsSecretAccessKey, date, region, stringToSign)

    const authorizationHeader = `${algorithm} Credential=${credential}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const response = await fetch(`https://${host}?${canonicalQueryString}`, {
        method: 'GET',
        headers: {
            'x-amz-date': amzdate, 
            'x-amz-content-sha256': payloadHash,
            'Authorization': authorizationHeader
        }
    });
    const responseText = await response.text();
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(responseText, "application/xml");
  
    const tagContent = (doc, tag) => Array.from(xmlDoc.getElementsByTagName(tag)).map(el => el.textContent)
    const keys = tagContent(xmlDoc, 'Key');
    const sizes = tagContent(xmlDoc, 'Size');
    const last_modifieds = tagContent(xmlDoc, 'LastModified')
  
    return keys.map((key, i) => ({
        key: key,
        size: sizes[i],
        last_modified: last_modifieds[i]
    }));
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const formattedBytes = parseFloat((bytes / Math.pow(1024, i)).toFixed(2));
    return `${formattedBytes} ${sizes[i]}`;
}

document.head.innerHTML = ''
document.body.innerHTML = '<input type="file" id="config-file" />'
document.querySelector('#config-file').addEventListener('change', function(event) {
    const reader = new FileReader();
    reader.onload = async function (e) {
        const fileContent = e.target.result;
        const config = Object.fromEntries(fileContent.split('\n').map(line => line.split('=')).filter(([x,y])=>x.length > 0))
        const bucket = window.location.host.replace('.s3.amazonaws.com','')

        const contents = await s3ListObjects(bucket, config.AWS_REGION, config.AWS_ACCESS_KEY, config.AWS_SECRET_ACCESS_KEY)

        const tbody = document.createElement('tbody')
        for (let item of contents) {
            const key = item.key.trim()
            const href = await s3GetObjectPresignedUrl(bucket, key, config.AWS_REGION, config.AWS_ACCESS_KEY, config.AWS_SECRET_ACCESS_KEY)
            const link = document.createElement('a')
            link.setAttribute('href', href)
            link.textContent = key
            const row = document.createElement('tr')
            const td_key = document.createElement('td')
            td_key.appendChild(link)
            row.appendChild(td_key)
            const td_size = document.createElement('td')
            td_size.textContent = formatBytes(item.size)
            row.appendChild(td_size)
            const td_last_modified = document.createElement('td')
            td_last_modified.textContent = item.last_modified
            row.appendChild(td_last_modified)
            tbody.appendChild(row)
        }
        document.body.innerHTML = `<table><thead><tr><th>Key</th><th>Size</th><th>Last Modified</th></tr></thead><tbody>${tbody.innerHTML}</tbody></table>`
    };
    reader.readAsText(event.target.files[0]);
});