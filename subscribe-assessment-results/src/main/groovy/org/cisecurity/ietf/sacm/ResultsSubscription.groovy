package org.cisecurity.ietf.sacm

import groovy.xml.XmlUtil
import groovyx.net.http.ContentType
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.RESTClient
import org.jivesoftware.smack.XMPPException
import org.jivesoftware.smackx.pubsub.ItemPublishEvent
import org.jivesoftware.smackx.pubsub.LeafNode
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.jivesoftware.smackx.pubsub.listener.ItemEventListener
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 3/2/2018.
 */
class ResultsSubscription {
	def log = LoggerFactory.getLogger(ResultsSubscription.class)

	final String NODE_NAME = "AssessmentResults" //AssessmentResults

	String jid
	LeafNode content

	String url
	String token

	/**
	 * Subscribe to the content node
	 * @param psm
	 * @return
	 */
	def subscribe(PubSubManager psm) {
		log.info "Attempting to retrieve topic --> ${NODE_NAME}"

		try {
			content = psm.getLeafNode(NODE_NAME)

			log.info "Found topic --> ${NODE_NAME}"

			content.addItemEventListener(new UploadExecutor(url: url, token: token))

			def subs = content.subscriptions
			def found = subs.find { s -> s.jid == jid }
			if (!found) {
				log.info "Subscribing JID --> ${jid} to topic --> ${NODE_NAME}"
				content.subscribe(jid)
			} else {
				log.info "JID --> ${jid} is already subscribed to topic --> ${NODE_NAME}"
			}
		} catch (XMPPException.XMPPErrorException e) {
			log.error "Exception when retrieving topic --> ${NODE_NAME}", e
		}
	}
}

class UploadExecutor implements ItemEventListener {
	def log = LoggerFactory.getLogger(UploadExecutor.class)

	def url
	def token
	def xmlParser

	/**
	 * Get an XML Parser, creating and properly configuring it if need be
	 * @return
	 */
	def getParser() {
		if (!xmlParser) {
			xmlParser = new XmlParser(false, false)
			xmlParser.setFeature("http://xml.org/sax/features/external-general-entities", false)
		}
		return xmlParser
	}

	@Override
	void handlePublishedItems(ItemPublishEvent items) {
		log.info "Entering published item handler..."
		log.info "  URL: ${url}"
		log.info "Token: ${token}"
		def b

		// Each item's payload is a node that looks like this:
		// "<arf_get_url xmlns=\"pubsub:arf:url\">GET URL</arf_get_url>"
		items.items.each { i ->
			log.info " Item: ${i.toXML()}"

			def inode = getParser().parseText(i.toXML())
			def pnode = inode.children()[0]

			// Obtain the GET URL
			def getUrl = pnode.text()

			def pos = getUrl.lastIndexOf("/")
			def reportName = getUrl.substring(pos + 1)

			// Download the file
			def rest = new RESTClient(getUrl)
			rest.ignoreSSLIssues()

			def emptyHeaders = [:]
			emptyHeaders."Accept" = 'application/xml'

			def restresponse = rest.get(headers: emptyHeaders)

			log.info "Status: ${restresponse.status}"
			def arf = new String(restresponse.data.bytes)

//			log.info "Writing downloaded file..."
//			new File("C:\\Temp\\${reportName}").withWriter { w ->
//				w.write XmlUtil.serialize(restresponse.data)
//			}

			def http = new HTTPBuilder(url)
			http.ignoreSSLIssues()

			def postHeaders = ["Authorization": "Bearer=${token}"]

			http.handler.success = {
				" - Assessment report successfully uploaded to ${url}"
			}

			http.handler.failure = { resp ->
				" - Unexpected failure: ${resp.statusLine}"
			}

			http.handler."401" = { resp ->
				" - Assessment failed to upload to ${url}. Authentication Failure.  Please ensure your authentication token is correct."
			}

			http.handler."500" = { resp ->
				" - Assessment failed to upload to ${url}. Response Status: ${resp.statusLine}"
			}

			// Actually send the POST
			def result = http.post(
				body: [
					"report-name": reportName,
					"ciscat-report": arf ],
				headers: postHeaders)

			log.info result
		}



		// Send the HTTP POST to CCPD
	}

}