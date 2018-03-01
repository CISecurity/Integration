package org.cisecurity.ietf.sacm

import groovy.xml.XmlUtil
import groovyx.net.http.ContentType
import groovyx.net.http.RESTClient
import org.cisecurity.assessor.util.AssessorUtilities
import org.jivesoftware.smack.SmackException.NoResponseException
import org.jivesoftware.smack.XMPPException
import org.jivesoftware.smackx.httpfileupload.HttpFileUploadManager
import org.jivesoftware.smackx.httpfileupload.element.Slot
import org.jivesoftware.smackx.pubsub.LeafNode
import org.jivesoftware.smackx.pubsub.PayloadItem
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.jivesoftware.smackx.pubsub.SimplePayload
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 2/26/2018.
 */
class ResultsPublisher {
	def log = LoggerFactory.getLogger(ResultsPublisher.class)

	final String NODE_NAME = "AssessmentResults"

	HttpFileUploadManager hfum
	LeafNode results



	/**
	 * Subscribe to the content node
	 * @param psm
	 * @return
	 */
	def subscribe(PubSubManager psm) {
		log.info "Service Discovered?  ${hfum.isUploadServiceDiscovered()}"

		log.info "Attempting to retrieve topic --> ${NODE_NAME}"

		try {
			results = psm.getLeafNode(NODE_NAME)

			log.info "Found topic --> ${NODE_NAME}"
		} catch (XMPPException.XMPPErrorException e) {
			log.error "Exception when retrieving topic --> ${NODE_NAME}", e
		}
	}

	def publish(def assessmentResults = []) {
		if (assessmentResults.size() > 0) {
			assessmentResults.each { fp ->
				def arf = new File(fp)
				def ar = AssessorUtilities.instance.getParser().parse(arf)

				def rootBasename = AssessorUtilities.instance.getElementBasename(ar.name())

				if (rootBasename == "asset-report-collection") {
					def collection = ar."**".find { n ->
						n instanceof Node && AssessorUtilities.instance.getElementBasename(n.name()) == "data-stream-collection"
					}
					if (collection) {
						def collectionId = collection.@id.toString()

						log.info "Constructing (ARF) payload for collection id --> ${collectionId}..."

						log.info "Getting Slot..."
						Slot slot = hfum.requestSlot(arf.name, arf.length())

						log.info "GET URL --> ${slot.getUrl}"
						log.info "PUT URL --> ${slot.putUrl}"

						def rest = new RESTClient(slot.putUrl)
						rest.ignoreSSLIssues()
						def restresponse = rest.put(
							contentType: ContentType.XML,
							body: arf.text,
							headers: [Accept: "application/xml"]
						)

						if (restresponse.status == 201) {
							def payloadContent =
								"<arf_get_url xmlns=\"pubsub:arf:url\">${slot.getUrl.toString()}</arf_get_url>"
							def sp = new SimplePayload(
								"arf_get_url",
								"pubsub:arf:url",
								payloadContent
							)
							def pi = new PayloadItem(collectionId, sp)

							// Publish an Item with payload
							try {
								results.publish(pi)

								log.info "Published"
							} catch (NoResponseException nre) {
								log.error "No Response Exception: Probably a timeout", nre
							}
						} else {
							log.info "File upload response status == ${restresponse.status}"
						}
					}
				} else {
					log.error "Invalid payload (${rootBasename}) for topic."
				}
			}
		}
	}
}
