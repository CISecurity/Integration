package org.cisecurity.ietf.sacm

import groovyx.net.http.ContentType
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.Method
import groovyx.net.http.RESTClient
import org.cisecurity.assessor.util.AssessorUtilities
import org.jivesoftware.smack.AbstractXMPPConnection
import org.jivesoftware.smack.ConnectionConfiguration
import org.jivesoftware.smack.tcp.XMPPTCPConnection
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration
import org.jivesoftware.smackx.httpfileupload.HttpFileUploadManager
import org.jivesoftware.smackx.httpfileupload.UploadProgressListener
import org.jivesoftware.smackx.httpfileupload.element.Slot
import org.slf4j.LoggerFactory

import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.SecureRandom

/**
 * File Upload Test
 * Created by wmunyan on 2/27/2018.
 */
class FileUploadTest {
	def log = LoggerFactory.getLogger(FileUploadTest.class)

	XMPPTCPConnectionConfiguration config
	AbstractXMPPConnection connection
	HttpFileUploadManager manager

	/**
	 * Entry
	 */
	static void main(String[] args) {
		new FileUploadTest().execute()
	}

	/**
	 * Execution
	 */
	def execute() {
		log.info "[START] File Upload Test"
		initialize()
		log.info "[ END ] File Upload Test"
	}

	/**
	 * Initialization
	 */
	def initialize() {
		log.info "Loading Assessor properties..."
		AssessorUtilities.instance.userProperties = new Properties()
		AssessorUtilities.instance.userProperties.load(getClass().getResourceAsStream("/assessor.properties"))

		log.info "Loading XMPP connection properties..."
		Properties properties = new Properties()
		properties.load(getClass().getResourceAsStream("/conn.properties"))

		log.info "Configuring XMPP connection..."
		config = XMPPTCPConnectionConfiguration.builder()
			.setUsernameAndPassword(properties.user, properties.password)
			.setXmppDomain(properties.xmppdomain)
			.setHost(properties.host)
			.setPort(Integer.parseInt(properties.port))
			.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
			.build()

		log.info "Connecting to XMPP server as user ${properties.user}..."
		connection = new XMPPTCPConnection(config)
		connection.setReplyTimeout(600000) // Reply timeout == 600 sec.
		connection.connect().login()

		log.info "Getting the HttpFileUploadManager..."

		manager = HttpFileUploadManager.getInstanceFor(connection)
		log.info "Service Discovered?  ${manager.isUploadServiceDiscovered()}"

		def p = "C:\\_Development\\Projects\\Assessor-CLI\\reports"
		def f = "CIS-CAT-DEV-CIS_Microsoft_Windows_10_Enterprise_Release_1703_Benchmark-ARF-20180205T191833Z.xml"

		def file = new File("${p}\\${f}")
		def upl  = new UPL()

		log.info "Getting Slot..."
		Slot slot = manager.requestSlot(file.name, file.length())
		def slotHeaders = slot.headers

		log.info "GET URL --> ${slot.getUrl}"
		log.info "PUT URL --> ${slot.putUrl}"

		def rest = new RESTClient(slot.putUrl)
		rest.ignoreSSLIssues()
		def restresponse = rest.put(
			contentType: ContentType.XML,
			body: file.text,
			headers: [Accept: "application/xml"]
		)

		println("Status: " + restresponse.status)
		if (restresponse.data) {
			println("Content Type: ${restresponse.contentType}")
			println("Headers: ${restresponse.getAllHeaders()}")
			println("Body:\n${restresponse.data}")
		}

//		log.info "Starting HTTPBuilder upload"
//		def http = new HTTPBuilder(slot.putUrl)
//		http.ignoreSSLIssues()
//		http.headers["Accept"] = "application/xml"
//
//		http.request(Method.PUT, ContentType.XML) { req ->
//
//			body = file
//
//			response.success = {
//				println " - Assessment report successfully uploaded to ${slot.putUrl}"
//			}
//
//			response.failure = { resp ->
//				println " - Unexpected failure: ${resp.statusLine}"
//			}
//
//			response."401" = { resp ->
//				println " - Assessment failed to upload to ${slot.putUrl}. Authentication Failure.  Please ensure your authentication token is correct."
//			}
//
//			response."500" = { resp ->
//				println " - Assessment failed to upload to ${slot.putUrl}. Response Status: ${resp.statusLine}"
//			}
//
//		}
//		log.info "Finishing HTTPBuilder upload"

//		log.info "Starting upload..."
//
//		try {
//			def url = manager.uploadFile(file, upl)
//
//			log.info "Upload complete."
//		} catch (Exception e) {
//			log.error "Exception.  Timed out?", e
//		}

		connection.disconnect()
	}
}

class UPL implements UploadProgressListener {
	@Override
	void onUploadProgress(long uploadedBytes, long totalBytes) {
		println "Uploaded ${uploadedBytes}/${totalBytes}"
	}
}