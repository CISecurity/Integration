package org.cisecurity.ietf.sacm

import groovy.xml.XmlUtil
import groovyx.net.http.ContentType
import groovyx.net.http.RESTClient
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 2/28/2018.
 */
class FileDownloadTest {
	def log = LoggerFactory.getLogger(FileDownloadTest.class)

	def url = "https://ip-0a1e0af4:7443/httpfileupload/83da0676-5383-4c2b-8a5d-ac47b1d233eb/CIS-CAT-DEV-CIS_Microsoft_Windows_10_Enterprise_Release_1703_Benchmark-ARF-20180205T191833Z.xml"

	static void main(String[] args) {
		new FileDownloadTest().download()
	}

	def download() {
		def rest = new RESTClient(url)
		rest.ignoreSSLIssues()
		def restresponse = rest.get(contentType: ContentType.XML)

		log.info "Status: ${restresponse.status}"
		def arf = restresponse.data
		log.info XmlUtil.serialize(arf)
	}
}
