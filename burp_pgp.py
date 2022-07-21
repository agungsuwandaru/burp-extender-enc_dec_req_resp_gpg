from burp import IBurpExtender, IHttpListener
import os
from subprocess import check_output
import commands

class BurpExtender(IBurpExtender, IHttpListener):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.registerHttpListener(self)
    callbacks.setExtensionName("PGP")
    print("Hello Burp")
    # output = os.system("dir C:")
    # output = commands.getstatus('dir C:')
    # print (output)
    output = check_output("cd", shell=True)
    print (output)
    callbacks.issueAlert("Hello alerts!")

  def getResponseHeadersAndBody(self, content):
    response = content.getResponse()
    response_data = self._helpers.analyzeResponse(response)
    headers = list(response_data.getHeaders() or '')
    body = response[response_data.getBodyOffset():].tostring()
    return headers, body

  def getRequestHeadersAndBody(self, content):
    request = content.getRequest()
    request_data = self._helpers.analyzeResponse(request)
    headers = list(request_data.getHeaders() or '')
    body = request[request_data.getBodyOffset():].tostring()
    return headers, body

  def processHttpMessage(self, tool, is_request, content):
    if is_request:
        request_headers, request_body = self.getRequestHeadersAndBody(content)
        # modify body
        f = open("request-burp.txt", "wb")
        f.write(request_body)
        print(request_body)
        f.close()
        output = check_output("dir", shell=True)
        print (output)
        request_body = check_output("type request-burp.txt | gpg --cipher-algo AES256 --digest-algo SHA256 --compress-algo ZIP -a -e -s -r TARGET_PUBLIC_KEY", shell=True)       
        print(request_body)
        new_request = self._helpers.buildHttpMessage(request_headers, request_body[:-2])
        content.setRequest(new_request)
        return
    response_headers, response_body = self.getResponseHeadersAndBody(content)
    # modify body
    f = open("response-burp.txt", "wb")
    f.write(response_body)
    f.close()
    response_body = check_output("type response-burp.txt | gpg --decrypt", shell=True)
    new_response = self._helpers.buildHttpMessage(response_headers, response_body)
    content.setResponse(new_response)
