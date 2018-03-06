package org.cisecurity.ietf.sacm.tst

import groovy.xml.XmlUtil
import groovyx.net.http.ContentType
import groovyx.net.http.RESTClient
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 2/28/2018.
 */
class FileDownloadTest {
	def log = LoggerFactory.getLogger(FileDownloadTest.class)

	def url = "https://ip-0a1e0af4:7443/httpfileupload/b757b65a-a568-40c1-b5f8-902080b9d21e/CIS-CAT-DEV-CIS_Microsoft_Windows_10_Enterprise_Release_1607_Benchmark-ARF-20180303T155826Z.xml"

	static void main(String[] args) {
		new FileDownloadTest().download()
	}

	def download() {
		def rest = new RESTClient(url)
		rest.ignoreSSLIssues()

		def emptyHeaders = [:]
		emptyHeaders."Accept" = 'application/xml'
		emptyHeaders."Prefer" = 'test'

		def response = rest.get(headers: emptyHeaders)

		println("Status: " + response.status)
		if (response.data) {
			//println("Content Type: " + response.contentType)
			println("Headers: " + response.getAllHeaders())
			def x = new String(response.data.bytes)
			new File("C:\\Temp\\temp.xml").withWriter { w -> w.write x }
		}

//		def restresponse = rest.get(contentType: ContentType.XML)
//
//		log.info "Status: ${restresponse.status}"
//		log.info "Response Type: ${restresponse.data.type}"
//		def xmlOutput = new StringWriter()
//		def xmlNodePrinter = new XmlNodePrinter(new PrintWriter(xmlOutput))
//		xmlNodePrinter.print(restresponse.data)
//
//		new File("C:\\Temp\\temp.xml").withWriter { w ->
//			w.write xmlOutput.toString()
//		}
	}
}
