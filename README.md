# polyfill.io-script-detection

In a significant supply chain attack, over 100,000 websites using Polyfill[.]io, a popular JavaScript CDN service, were compromised.
This Burp Suite extension detects the usage of scripts from the polyfill.io CDN in HTTP responses. 

If cdn.polyfill.io is used in an application like the one below, if this value is used in the script tag, the extension will detect it.

## How to use

You just need to download the extension. If a vulnerability is detected, you will see that is automatically detected in the sitemap issue section.
Extension written in Java. All you have to do is import this file "out/artifacts/polyfilldetection_jar/polyfilldetection.jar" as an extension and load it.




## Example request
<pre>
GET /polyfill.js HTTP/1.1
Host: cdn.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://localhost:8000/
Sec-Fetch-Dest: script
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: cross-site
Te: trailers
Connection: keep-alive
</pre>

Example vulnerability detection is as follows.

![image](https://github.com/batuhaniskr/polyfill.io-script-detection/assets/17202632/2d8d1844-73df-4729-bea7-9758c98d7d04)
