package com.apptivo.view.dao.servlet.v6.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.apptivo.app.service.BaseElasticService;
import com.apptivo.model.dao.common.AppBaseDAO;
import com.apptivo.model.dao.es.ElasticSearchDAO;
import com.apptivo.model.dao.esign.ESignConstants;
import com.apptivo.model.index.athena.IdxFirmESignDocument;
import com.apptivo.model.index.cf.IdxCfToken;
import com.apptivo.model.index.common.IdxFirmBranding;
import com.apptivo.model.index.common.IdxObject;
import com.apptivo.model.index.esign.IdxDocChangeRequest;
import com.apptivo.model.index.esign.IdxESignConfiguration;
import com.apptivo.model.index.esign.IdxESignDocument;
import com.apptivo.model.index.esign.IdxESignSigner;
import com.apptivo.model.index.esign.IdxEsignDocumentPage;
import com.apptivo.model.index.fin.IdxEsignatureHistory;
import com.apptivo.view.cf.service.CfTokenService;
import com.apptivo.view.service.actioncenter.ESignEventActionService;
import com.sirahu.apptivo.common.logging.MessageLogger;
import com.sirahu.apptivo.common.util.AppUtil;
import com.sirahu.apptivo.common.util.DateUtil;
import com.sirahu.apptivo.common.utils.AppEncryptionUtil;
import com.sirahu.apptivo.model.framework.util.AppConstants;
import com.sirahu.apptivo.model.framework.util.ObjectConstants;
import com.sirahu.apptivo.view.framework.util.AppHttpUtil;

public class SignService extends BaseElasticService {

	private static final MessageLogger logger = MessageLogger.getLogger(SignService.class);
	private static SignService instance;

	static {
		instance = new SignService();
	}

	private SignService() {

	}

	public static SignService getInstance() {
		return instance;
	}

	/**
	 * This method used to verify the Multi-Factor Authentication is enabled or
	 * not.
	 *
	 * @param firmId
	 * @param documentId
	 * @param signerId
	 * @param request
	 * @return
	 */
	public Map<String, Object> isMfaEnabled(final String id, final String encodedSignerId,
			final HttpServletRequest request) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();
		final Long signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));

		results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
		try {
			final String[] includeFields = {};
			final String[] excludeFields = { ESignConstants.ESIGN_DOCUMENT_PAGES,
					ESignConstants.ESIGN_SIGNED_DOCUMENT };

			final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId, documentId,
					includeFields, excludeFields);
			final boolean isValidDoc = ESignatureService.getInstance().validateDocBySignerId(idxESignDocument,
					signerId);

			// Setting up the Branding details
			if (isValidDoc && idxESignDocument != null && idxESignDocument.getbId() != null) {
				final IdxFirmBranding firmBranding = ElasticSearchDAO.getInstance().getDocument(firmId,
						IdxFirmBranding.class, ObjectConstants.OBJECT_FIRM_BRANDING, idxESignDocument.getbId());
				results.put(ESignConstants.BRAND_DATA, firmBranding);
			}

			// Multi-Factor Authentication Details
			if (isValidDoc && idxESignDocument != null
					&& ObjectConstants.OBJECT_ESIGN_DOCUMENT
							.equals(idxESignDocument.getAssociatedObject().getObjectId())
					&& ESignConstants.SEND_SIGN.equals(idxESignDocument.getSignType())) {
				final IdxESignConfiguration idxESignConfiguration = AppBaseDAO.getInstance().getConfigData(firmId,
						IdxESignConfiguration.class, ObjectConstants.OBJECT_ESIGN_CONFIGURATION_DATA);
				if (idxESignConfiguration != null
						&& ESignConstants.SIGNER_AUTH_EMAIL.equals(idxESignConfiguration.getActiveSignerAuthType())) {
					results.putAll(
							ESignatureService.getInstance().signerAuthEmail(idxESignDocument, signerId, request));
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
					return results;
				}
			}
		} catch (Exception exception) {
			logger.error(firmId, "ESignatureService:isMfaEnabled:exception:", exception);
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		}
		results.put("isMfaEnabled", AppConstants.NO);
		return results;
	}

	/**
	 * This method used to resend the Auth Code
	 *
	 * @param firmId
	 * @param documentId
	 * @param signerId
	 * @return
	 */
	public Map<String, Object> resendAuthCode(final Long firmId, final Long documentId, final Long signerId) {
		final Map<String, Object> result = new HashMap<>();
		try {

			final String ctxId = firmId + "_" + documentId + "_" + signerId;

			final IdxCfToken idxCfToken = CfTokenService.getInstance().getCfToken(ctxId, null);
			final String[] includeFields = {};
			final String[] excludeFields = { ESignConstants.ESIGN_DOCUMENT_PAGES,
					ESignConstants.ESIGN_SIGNED_DOCUMENT };

			final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId, documentId,
					includeFields, excludeFields);

			final IdxESignSigner idxESigner = idxESignDocument.getESignSignerBySignerId(signerId);

			final Calendar calendar = Calendar.getInstance();
			final Date currentDate = calendar.getTime();
			calendar.add(Calendar.HOUR, 1);
			final String currentDateAddHour = DateUtil.getEsDateFormat().format(calendar.getTime());

			final SimpleDateFormat sdfWithoutTimezone = new SimpleDateFormat(DateUtil.format_mdyhms);

			final Date creationDate = DateUtil.parseDate(idxCfToken.getCreationDate(), sdfWithoutTimezone, null);

			final Long dateDiff = DateUtil.difference(creationDate, currentDate);

			if (dateDiff > ESignConstants.PASSCODE_RESET_TIME) {
				final IdxCfToken cfToken = CfTokenService.getInstance().createCfToken(ctxId,
						ObjectConstants.OBJECT_ESIGN_DOCUMENT, documentId.toString(), currentDateAddHour);

				String signerName = null;
				String emailId = null;
				if (idxESigner == null && signerId.equals(idxESignDocument.getCreatedBy())) {
					final IdxObject senderDetails = idxESignDocument.getSenderDetails();
					signerName = senderDetails.getObjectRefName();
					emailId = senderDetails.getEmailId();

					// Updating the tokenId in IdxESignSigner
					senderDetails.setTId(idxCfToken.getId());
					ESignatureService.getInstance().updateSenderDetailsByScript(firmId, documentId, senderDetails);
				} else if (idxESigner != null) {
					signerName = idxESigner.getObjectRefName();
					emailId = idxESigner.getPrimaryEmailId();

					// Updating the tokenId in IdxESignSigner
					idxESigner.settId(cfToken.getId());
					ESignatureService.getInstance().updateSignerByScript(firmId, documentId,
							idxESignDocument.getSigners());
				}

				// Sending Authentication Email to Signer
				ESignatureService.getInstance().sendAuthMail(firmId, idxESignDocument, signerName,
						emailId, AppEncryptionUtil.dycrypt(cfToken.getOtp()));

				result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
				return result;
			} else {
				result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
				result.put(AppConstants.RESULT_REASON, "PWD_RESET_TIME");
				result.put(AppConstants.RESULT_DATA, dateDiff);
			}
			result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		} catch (Exception exception) {
			logger.error(firmId, "ESignatureService:resendAuthCode:exception:", exception);
			result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		}
		return result;
	}

	/**
	 * This method used to get the document
	 *
	 * @param id
	 * @param encodedSignerId
	 * @param authCode
	 * @param request
	 * @return
	 *
	 * @author Sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> getDocumentBySigner(final String id, final String encodedSignerId, final String authCode,
			final HttpServletRequest request) {
		final Map<String, Object> results = new HashMap<>();

		final String clientIpAddress = AppHttpUtil.getClientIPAddress(request);
		final String userAgent = AppHttpUtil.getUserAgent(request);

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();
		final String timeZoneId = firmESignDocument.getTimeZoneId();
		final String dateFormat = firmESignDocument.getDateFormat();

		Long signerId = null;
		if (encodedSignerId != null) {
			signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
		}

		final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getESignDocumentBySignerId(firmId,
				documentId, signerId);
		logger.info(firmId, "SignService:getDocument:idxESignDocument:" + idxESignDocument);

		// For Getting the Branding Details
		if (idxESignDocument != null && idxESignDocument.getbId() != null) {
			final IdxFirmBranding firmBranding = ElasticSearchDAO.getInstance().getDocument(firmId,
					IdxFirmBranding.class, ObjectConstants.OBJECT_FIRM_BRANDING, idxESignDocument.getbId());
			results.put(ESignConstants.BRAND_DATA, firmBranding);
		} else {
			final List<IdxFirmBranding> firmBrandings = ESignatureService.getInstance().getFirmBranding(firmId, null);
			results.put(ESignConstants.BRAND_DATA,
					AppUtil.checkListisNullOrNot(firmBrandings) ? firmBrandings.get(0) : null);
		}

		if (idxESignDocument != null
				&& ObjectConstants.OBJECT_ESIGN_DOCUMENT.equals(idxESignDocument.getAssociatedObject().getObjectId())
				&& ESignConstants.SEND_SIGN.equals(idxESignDocument.getSignType())) {
			final Map<String, String> authResult = ESignatureService.getInstance().isSignerAuthCodeValid(firmId,
					signerId, idxESignDocument, authCode, clientIpAddress, userAgent, request);

			if (AppConstants.YES.equals(authResult.get("IS_SIGNER_AUTH_ENABLED"))
					&& !AppConstants.YES.equals(authResult.get("IS_SIGNER_AUTHORIZED"))) {
				results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
				results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_INVALID_AUTH_CODE);
				results.putAll(authResult);
				return results;
			}
		}

		final boolean isExpired = ESignatureService.getInstance().isDocExpired(idxESignDocument);

		// For Estimate, checking for the valid status
		boolean isValidEstimate = true;
		if (idxESignDocument != null
				&& ObjectConstants.OBJECT_ESTIMATE.equals(idxESignDocument.getAssociatedObject().getObjectId())) {
			isValidEstimate = ESignatureService.getInstance().isValidEstimate(firmId,
					idxESignDocument.getAssociatedObject().getObjectRefId());
		}

		if ((idxESignDocument != null
				&& ESignConstants.ESIGN_DOCUMENT_STATUS_VOID.equalsIgnoreCase(idxESignDocument.getStatusCode()))
				|| (!isValidEstimate)) {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOCUMENT_VOIDED);
			return results;
		}

		if (idxESignDocument != null && (AppConstants.OBJECT_STATUS_ACTIVE.equals(idxESignDocument.getObjectStatus())
				|| !ObjectConstants.OBJECT_ESIGN_DOCUMENT.equals(idxESignDocument.getAssociatedObject().getObjectId()))
				&& !isExpired && isValidEstimate) {
			ESignatureService.getInstance().createViewHistoryBySignType(firmId, signerId, idxESignDocument,
					clientIpAddress, userAgent);
			idxESignDocument.setDocumentData("");
			idxESignDocument.setSignedDocument("");

			idxESignDocument.formatDateValues(TimeZone.getTimeZone(timeZoneId), dateFormat);

			int totalPages = idxESignDocument.getDocumentPages().size();
			final List<IdxEsignDocumentPage> idxESignDocPages = new ArrayList<>();
			idxESignDocPages.add(idxESignDocument.getDocumentPages().get(0));
			idxESignDocument.setDocumentPages(idxESignDocPages);

			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
			results.put(ESignConstants.RESPONSE_PARAM_DOCUMENT, idxESignDocument);
			results.put(ESignConstants.RESPONSE_PARAM_TOTAL_PAGES, totalPages);
			results.put(AppConstants.DATE_FORMAT, dateFormat);

			// Preparing the legal disclosure
			results.putAll(ESignatureService.getInstance().prepareLegalDisclosure(idxESignDocument, signerId));
		} else if (idxESignDocument == null) {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		} else if (AppConstants.OBJECT_STATUS_INACTIVE.equals(idxESignDocument.getObjectStatus())) {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_DELETED);
		} else if (isExpired) {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_EXPIRED);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		}
		return results;
	}

	/**
	 * This method used to get the next document Page by page Index.
	 *
	 * @param id
	 * @param documentPageIndex
	 * @param encodedSignerId
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> getNextDocumentPage(final String id, Long documentPageIndex, final String encodedSignerId) {
		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();

		Long signerId = null;

		if (encodedSignerId != null) {
			signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
		}

		final Map<String, Object> results = new HashMap<>();

		final String[] include = { AppConstants.CREATED_BY, ESignConstants.SIGNERS, ESignConstants.SIGN_TYPE };
		final String[] exclude = {};

		final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId, documentId,
				include, exclude);
		logger.info(firmId, "SignService:getNextDocumentPage:idxESignDocument:" + idxESignDocument);

		if (idxESignDocument != null) {
			boolean isSigner = false;
			boolean isCreatedBy = false;

			if (idxESignDocument.getCreatedBy().equals(signerId)) {
				isCreatedBy = true;
			}

			if (!isCreatedBy && signerId != null) {
				for (IdxESignSigner signer : idxESignDocument.getSigners()) {
					if (signerId.equals(signer.geteSignSignerId())) {
						isSigner = true;
						break;
					}
				}
			}

			if (isCreatedBy || isSigner || ESignConstants.IN_PERSON_SIGN.equals(idxESignDocument.getSignType())) {
				final IdxEsignDocumentPage page = ESignatureService.getInstance().getDocPageByIndex(firmId, documentId,
						++documentPageIndex);
				if (page != null) {
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
					results.put(ESignConstants.RESPONSE_PARAM_DOCUMENT, page);
				} else {
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
				}
				return results;
			} else {
				results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
				results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_INVALID_SIGNER);
			}
			return results;
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS_FOR_ID);
		}
		return results;
	}

	/**
	 * This method used to sign the document
	 *
	 * @param id
	 * @param encodedSignerId
	 * @param eSignAttributes
	 * @param request
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> signDocument(final String id, final String encodedSignerId, final String eSignAttributes,
			final HttpServletRequest request) {
		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		
		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();
		final String timeZoneId = firmESignDocument.getTimeZoneId();

		Long signerId = null;
		if (encodedSignerId != null) {
			signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
		}

		final Map<String, Object> results = new HashMap<>();

		final String clientIpAddress = AppHttpUtil.getClientIPAddress(request);
		final String userAgent = AppHttpUtil.getUserAgent(request);

		final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getESignDocumentBySignerId(firmId,
				documentId, signerId);
		logger.info(firmId, "SignService:signDocument:idxESignDocument:" + idxESignDocument);

		if (idxESignDocument != null && eSignAttributes != null) {
			// Sign Document based on signature type (In-Person Sign/Send
			// E-Sign).
			if (ESignConstants.IN_PERSON_SIGN.equals(idxESignDocument.getSignType())) {
				// Preparing e-Sign attributes for IdxESignDOcument and
				// Associated object
				ESignatureService.getInstance().saveESignDocumentAttributes(idxESignDocument, eSignAttributes, signerId,
						clientIpAddress, userAgent, true);

				// prepare signedDocument with eSignAttributes.
				final Map<String, String> result = ESignatureService.getInstance()
						.prepareSignedPDFInBytes(idxESignDocument);

				ESignatureService.getInstance().signInPersonDocument(firmId, idxESignDocument, result, timeZoneId,
						clientIpAddress, userAgent);
			} else {
				ESignatureService.getInstance().signESignDocument(firmId, documentId, signerId, eSignAttributes,
						timeZoneId, clientIpAddress, userAgent, true);
			}

			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		}
		return results;
	}

	/**
	 * This method used to verify the hash value
	 *
	 * @param id
	 * @param encodedSignerId
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, String> verifyHashValue(final String id, final String encodedSignerId) {
		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();

		Long signerId = null;
		if (encodedSignerId != null) {
			signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
		}

		final String[] include = { AppConstants.CREATED_BY, ESignConstants.SIGNERS, ESignConstants.SIGN_TYPE,
				ESignConstants.STATUS_NAME };
		final String[] exclude = {};

		final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId, documentId,
				include, exclude);
		final boolean isValidDocument = ESignatureService.getInstance().validateDocBySignerId(idxESignDocument,
				signerId);

		Long objectId;
		String objectRefId;

		if (idxESignDocument != null && isValidDocument) {
			if (ESignConstants.SEND_SIGN.equalsIgnoreCase(idxESignDocument.getSignType())) {
				final IdxEsignatureHistory idxESignHistory = ESignatureService.getInstance()
						.getESignHistoryBySignerId(firmId, documentId);
				if (idxESignHistory != null) {
					objectId = ObjectConstants.OBJECT_ESIGNATURE_HISTORY;
					objectRefId = idxESignHistory.getHistoryId();
				} else if (ESignConstants.ESIGN_DOCUMENT_STATUS_NEW.equals(idxESignDocument.getStatusName())
						|| ESignConstants.ESIGN_DOCUMENT_STATUS_SENT.equals(idxESignDocument.getStatusName())) {
					objectId = ObjectConstants.OBJECT_ESIGN_DOCUMENT;
					objectRefId = documentId.toString() + "_o";
				} else {
					objectId = ObjectConstants.OBJECT_ESIGN_DOCUMENT;
					objectRefId = documentId.toString();
				}
			} else {
				objectId = ObjectConstants.OBJECT_ESIGN_DOCUMENT;
				objectRefId = documentId.toString();
			}
			return ESignatureService.getInstance().verifyHashValues(firmId, documentId, objectId, objectRefId);
		} else {
			final Map<String, String> result = new HashMap<>();
			result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			return result;
		}
	}

	/**
	 * This method used to print the ESign PDF.
	 *
	 * @param id
	 * @param encodedSignerId
	 * @param request
	 * @param response
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public String printESignPdf(final String id, final String encodedSignerId, final HttpServletRequest request,
			final HttpServletResponse response) {
		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();
		final Long signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));

		final String isRev = AppHttpUtil.getStringParameter(request, "isRev", null);
		final Long objId = AppHttpUtil.getLongParameter(request, AppConstants.STR_OBJECT_ID, null);
		final String objRefId = AppHttpUtil.getStringParameter(request, AppConstants.STR_OBJECT_REF_ID, null);

		final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getESignDocumentBySignerId(firmId,
				documentId, signerId);
		if (idxESignDocument != null) {
			ESignatureService.getInstance().printPDF(request, response, firmId, documentId, isRev, objId, objRefId);
			return AppConstants.RESULT_STATUS_SUCCESS;
		}
		return AppConstants.RESULT_STATUS_FAILURE;
	}

	/**
	 * This method used to download the Audit
	 *
	 * @param id
	 * @param encodedSignerId
	 * @param request
	 * @param response
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public String downloadAudit(final String id, final String encodedSignerId, final HttpServletRequest request,
			final HttpServletResponse response) {
		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();
		final TimeZone timeZone = TimeZone.getTimeZone(firmESignDocument.getTimeZoneId());

		Long signerId = null;
		if (encodedSignerId != null) {
			signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
		}

		final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getESignDocumentBySignerId(firmId,
				documentId, signerId);

		if (idxESignDocument != null) {
			return ESignatureService.getInstance().downloadAudit(firmId, documentId, idxESignDocument, timeZone,
					request, response);
		} else {
			final Map<String, String> result = new HashMap<>();
			result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			return AppUtil.convertToJson(result);
		}
	}

	/**
	 * This method used to get all comments.
	 *
	 * @param id
	 */
	public Map<String, Object> getAllComments(final String id) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:getAllComments:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final Long documentId = firmESignDocument.getDocumentId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();

			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
			results.put(AppConstants.RESULT_DATA,
					ESignatureService.getInstance().getAllComments(firmId, documentId, timeZoneId));
			return results;
		}
		results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		return results;
	}

	/**
	 * This method used to create comment
	 *
	 * @param id
	 * @param changeRequestData
	 * @param brandId
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> createComment(final String id, final String changeRequestData, final String brandId) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:createComment:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();
			final Long objectId = firmESignDocument.getObjectId();

			final IdxDocChangeRequest idxDocChangeRequest = AppUtil.convertFromJson(IdxDocChangeRequest.class,
					changeRequestData);

			if (idxDocChangeRequest != null) {
				final String[] includeFields = {};
				final String[] excludeFields = { ESignConstants.ESIGN_DOCUMENT_DATA,
						ESignConstants.ESIGN_DOCUMENT_PAGES, ESignConstants.ESIGN_SIGNED_DOCUMENT };

				final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId,
						Long.valueOf(idxDocChangeRequest.getDocumentId()), includeFields, excludeFields);
				final IdxESignSigner idxSigner = idxESignDocument
						.getESignSignerBySignerId(idxDocChangeRequest.getCreatedBy());

				final String currentDate = new SimpleDateFormat(DateUtil.format_mdyhms).format(new Date());

				idxDocChangeRequest.setCreationDate(currentDate);
				idxDocChangeRequest.setLastUpdateDate(currentDate);

				if (AppUtil.checkListisNullOrNot(idxDocChangeRequest.getMentions())) {
					ESignatureService.getInstance().sendChangeRequestNotification(idxDocChangeRequest,
							idxDocChangeRequest.getMentions(), objectId, brandId, idxESignDocument, idxSigner);
				}

				idxDocChangeRequest.setFirmId(firmId);
				ESignatureService.getInstance().indexDocChangeRequest(idxDocChangeRequest);

				// Action Center - Change Request
				if (ObjectConstants.OBJECT_ESIGN_DOCUMENT
						.equals(idxESignDocument.getAssociatedObject().getObjectId())) {
					ESignEventActionService.getInstance().produceActionQueue(firmId, idxESignDocument, idxSigner,
							idxDocChangeRequest, ESignConstants.AE_CODE_CHANGE_REQUESTED);
				}

				idxDocChangeRequest.formatDateValues(TimeZone.getTimeZone(timeZoneId));
				results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
				results.put(AppConstants.RESULT_DATA, idxDocChangeRequest);
				return results;
			}
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_CONVERSION_FAILED);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		}
		return results;
	}

	/**
	 * This method used to reply the comment.
	 *
	 * @param id
	 * @param changeRequestId
	 * @param changeRequestData
	 * @param brandId
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> replyComment(final String id, final String changeRequestId,
			final String changeRequestData, final String brandId) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:replyComment:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();
			final Long objectId = firmESignDocument.getObjectId();

			final IdxDocChangeRequest idxChangeRequestData = AppUtil.convertFromJson(IdxDocChangeRequest.class,
					changeRequestData);
			if (idxChangeRequestData != null) {
				final IdxDocChangeRequest parentChangeRequest = ElasticSearchDAO.getInstance().getDocument(firmId,
						IdxDocChangeRequest.class, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST, changeRequestId);
				// Action Center
				final String[] includeFields = {};
				final String[] excludeFields = { ESignConstants.ESIGN_DOCUMENT_DATA,
						ESignConstants.ESIGN_DOCUMENT_PAGES, ESignConstants.ESIGN_SIGNED_DOCUMENT };

				final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId,
						Long.valueOf(parentChangeRequest.getDocumentId()), includeFields, excludeFields);
				final IdxESignSigner idxSigner = idxESignDocument
						.getESignSignerBySignerId(idxChangeRequestData.getCreatedBy());

				if (parentChangeRequest != null) {
					final String currentDate = new SimpleDateFormat(DateUtil.format_mdyhms).format(new Date());

					idxChangeRequestData.setCreationDate(currentDate);
					idxChangeRequestData.setLastUpdateDate(currentDate);

					parentChangeRequest.getHistory().add(idxChangeRequestData);

					if (AppUtil.checkListisNullOrNot(idxChangeRequestData.getMentions())) {
						ESignatureService.getInstance().sendChangeRequestNotification(parentChangeRequest,
								idxChangeRequestData.getMentions(), objectId, brandId, idxESignDocument,idxSigner );
					}

					ElasticSearchDAO.getInstance().indexDocument(firmId, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST,
							changeRequestId, AppUtil.convertToJson(parentChangeRequest));

					// Action Center - Change Request
					if (ObjectConstants.OBJECT_ESIGN_DOCUMENT
							.equals(idxESignDocument.getAssociatedObject().getObjectId())) {
						ESignEventActionService.getInstance().produceActionQueue(firmId, idxESignDocument, idxSigner,
								idxChangeRequestData, ESignConstants.AE_CODE_CHANGE_REQUESTED);
					}

					parentChangeRequest.formatDateValues(TimeZone.getTimeZone(timeZoneId));
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
					results.put(AppConstants.RESULT_DATA, parentChangeRequest);
				} else {
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
					results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS_FOR_ID);
				}
				return results;
			}
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_CONVERSION_FAILED);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		}
		return results;
	}

	/**
	 * This method used to update the comment.
	 *
	 * @param id
	 * @param changeRequestId
	 * @param changeRequestData
	 * @param childIndex
	 * @param brandId
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> updateComment(final String id, final String changeRequestId,
			final String changeRequestData, final Integer childIndex, final String brandId) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:updateComment:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();
			final Long objectId = firmESignDocument.getObjectId();

			final IdxDocChangeRequest idxChangeRequestData = AppUtil.convertFromJson(IdxDocChangeRequest.class,
					changeRequestData);

			if (idxChangeRequestData != null) {
				final IdxDocChangeRequest parentChangeRequest = ElasticSearchDAO.getInstance().getDocument(firmId,
						IdxDocChangeRequest.class, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST, changeRequestId);

				// Action Center
				final String[] includeFields = {};
				final String[] excludeFields = { ESignConstants.ESIGN_DOCUMENT_DATA,
						ESignConstants.ESIGN_DOCUMENT_PAGES, ESignConstants.ESIGN_SIGNED_DOCUMENT };

				final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId,
						Long.valueOf(parentChangeRequest.getDocumentId()), includeFields, excludeFields);
				final IdxESignSigner idxSigner = idxESignDocument
						.getESignSignerBySignerId(idxChangeRequestData.getCreatedBy());

				if (parentChangeRequest != null) {

					if (childIndex != null) {
						final IdxDocChangeRequest idxDocChangeRequest = parentChangeRequest.getHistory()
								.get(childIndex);
						idxDocChangeRequest.setComments(idxChangeRequestData.getComments());
						idxDocChangeRequest
								.setLastUpdateDate(new SimpleDateFormat(DateUtil.format_mdyhms).format(new Date()));
						if (AppUtil.checkListisNullOrNot(idxChangeRequestData.getMentions())) {
							idxDocChangeRequest.setMentions(idxChangeRequestData.getMentions());
							ESignatureService.getInstance().sendChangeRequestNotification(parentChangeRequest,
									idxDocChangeRequest.getMentions(), objectId, brandId, idxESignDocument, idxSigner);
						}
					} else {
						parentChangeRequest.setComments(idxChangeRequestData.getComments());
						parentChangeRequest
								.setLastUpdateDate(new SimpleDateFormat(DateUtil.format_mdyhms).format(new Date()));
						if (AppUtil.checkListisNullOrNot(idxChangeRequestData.getMentions())) {
							parentChangeRequest.setMentions(idxChangeRequestData.getMentions());
							ESignatureService.getInstance().sendChangeRequestNotification(parentChangeRequest,
									parentChangeRequest.getMentions(), objectId, brandId, idxESignDocument, idxSigner);
						}
					}
					ElasticSearchDAO.getInstance().indexDocument(firmId, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST,
							changeRequestId, AppUtil.convertToJson(parentChangeRequest));

					// Action Center - Change Request
					if (ObjectConstants.OBJECT_ESIGN_DOCUMENT
							.equals(idxESignDocument.getAssociatedObject().getObjectId())) {
						ESignEventActionService.getInstance().produceActionQueue(firmId, idxESignDocument, idxSigner,
								idxChangeRequestData, ESignConstants.AE_CODE_CHANGE_REQUESTED);
					}

					parentChangeRequest.formatDateValues(TimeZone.getTimeZone(timeZoneId));

					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
					results.put(AppConstants.RESULT_DATA, parentChangeRequest);
				} else {
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
					results.put(AppConstants.RESULT_REASON, "Document doesn't exists for given changeRequestId");
				}
				return results;
			}
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_CONVERSION_FAILED);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		}
		return results;
	}

	/**
	 * This method used to resolve or reopen the comment
	 *
	 * @param id
	 * @param changeRequestId
	 * @param changeRequestData
	 * @param brandId
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> resolveOrReopenComment(final String id, final String changeRequestId,
			final String changeRequestData, final String brandId) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:resolveOrReopenComment:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();
			final Long objectId = firmESignDocument.getObjectId();

			final IdxDocChangeRequest idxChangeRequestData = AppUtil.convertFromJson(IdxDocChangeRequest.class,
					changeRequestData);

			if (idxChangeRequestData != null) {
				final IdxDocChangeRequest parentChangeRequest = ElasticSearchDAO.getInstance().getDocument(firmId,
						IdxDocChangeRequest.class, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST, changeRequestId);

				final String[] includeFields = {};
				final String[] excludeFields = { ESignConstants.ESIGN_DOCUMENT_DATA,
						ESignConstants.ESIGN_DOCUMENT_PAGES, ESignConstants.ESIGN_SIGNED_DOCUMENT };
				final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId,
						Long.valueOf(idxChangeRequestData.getDocumentId()), includeFields, excludeFields);
				final IdxESignSigner idxSigner = idxESignDocument
						.getESignSignerBySignerId(idxChangeRequestData.getCreatedBy());

				if (parentChangeRequest != null) {
					final String currentDate = new SimpleDateFormat(DateUtil.format_mdyhms).format(new Date());

					parentChangeRequest.setStatus(idxChangeRequestData.getStatus());
					parentChangeRequest.setLastUpdateDate(currentDate);

					idxChangeRequestData.setCreationDate(currentDate);
					idxChangeRequestData.setLastUpdateDate(currentDate);

					parentChangeRequest.getHistory().add(idxChangeRequestData);

					if (AppUtil.checkListisNullOrNot(idxChangeRequestData.getMentions())) {
						ESignatureService.getInstance().sendChangeRequestNotification(parentChangeRequest,
								idxChangeRequestData.getMentions(), objectId, brandId, idxESignDocument, idxSigner);
					}

					ElasticSearchDAO.getInstance().indexDocument(firmId, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST,
							changeRequestId, AppUtil.convertToJson(parentChangeRequest));
					parentChangeRequest.formatDateValues(TimeZone.getTimeZone(timeZoneId));

					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
					results.put(AppConstants.RESULT_DATA, parentChangeRequest);
				} else {
					results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
					results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS_FOR_ID);
				}
				return results;
			}
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_CONVERSION_FAILED);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		}
		return results;
	}

	/**
	 * This method used to delete the comment
	 *
	 * @param id
	 * @param changeRequestId
	 * @param childIndex
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> deleteComment(final String id, final String changeRequestId, final Integer childIndex) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();

			final IdxDocChangeRequest parentChangeRequest = ElasticSearchDAO.getInstance().getDocument(firmId,
					IdxDocChangeRequest.class, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST, changeRequestId);

			if (parentChangeRequest != null) {
				if (childIndex != null) {
					parentChangeRequest.getHistory().remove(childIndex.intValue());
					ElasticSearchDAO.getInstance().indexDocument(firmId, ObjectConstants.OBJECT_DOC_CHANGE_REQUEST,
							changeRequestId, AppUtil.convertToJson(parentChangeRequest));
				} else {
					ElasticSearchDAO.getInstance().deleteDocument(firmId,
							ObjectConstants.OBJECT_DOC_CHANGE_REQUEST.toString(), changeRequestId);
				}

				parentChangeRequest.formatDateValues(TimeZone.getTimeZone(timeZoneId));

				results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
				results.put(AppConstants.RESULT_DATA, parentChangeRequest);
				return results;
			}
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS_FOR_ID);
		} else {
			results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
			results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		}
		return results;
	}

	/**
	 * This method used to get the ESign Doc histories.
	 *
	 * @param id
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> getESignDocHistories(final String id) {
		final Map<String, Object> result = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final Long documentId = firmESignDocument.getDocumentId();
			final String timeZoneId = firmESignDocument.getTimeZoneId();

			result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
			result.put(AppConstants.RESULT_DATA, ESignatureService.getInstance().getESignDocHistories(firmId,
					documentId, TimeZone.getTimeZone(timeZoneId)));
			return result;
		}
		result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		result.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		return result;
	}

	/**
	 * This method used to request for reassign the document.
	 *
	 * @param id
	 * @param encodedSignerId
	 * @param reassign
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> requestReassign(final String id, final String encodedSignerId, final String reassign) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:requestReassign:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final Long documentId = firmESignDocument.getDocumentId();
			final Long signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
			results.putAll(ESignatureService.getInstance().reassignDocument(firmId, documentId, signerId, reassign));
			return results;
		}
		results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		return results;
	}

	/**
	 * This method used to reassign the document.
	 *
	 * @param id
	 * @param encodedSignerId
	 * @param request
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> reassignAction(final String id, final String encodedSignerId,
			final HttpServletRequest request) {
		final Map<String, Object> results = new HashMap<>();

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);
		logger.info(0L, "SignService:reassignAction:firmESignDocument:" + firmESignDocument);

		if (firmESignDocument != null) {
			final Long firmId = firmESignDocument.getFirmId();
			final Long documentId = firmESignDocument.getDocumentId();
			final Long reqSId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));

			results.putAll(ESignatureService.getInstance().reassignAction(firmId, documentId, reqSId, request));

			// For Getting the Branding Details
			final String[] includeFields = { ESignConstants.BID };
			final String[] excludeFields = {};
			final IdxESignDocument idxESignDocument = ESignatureService.getInstance().getDocument(firmId, documentId,
					includeFields, excludeFields);
			if (idxESignDocument != null && idxESignDocument.getbId() != null) {
				final IdxFirmBranding firmBranding = ElasticSearchDAO.getInstance().getDocument(firmId,
						IdxFirmBranding.class, ObjectConstants.OBJECT_FIRM_BRANDING, idxESignDocument.getbId());
				results.put(ESignConstants.BRAND_DATA, firmBranding);
			}
			return results;
		}
		results.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		results.put(AppConstants.RESULT_REASON, ESignConstants.RESPONSE_REASON_DOC_NOT_EXISTS);
		return results;
	}

	/**
	 * This method used to get the branding details from the signing page
	 *
	 * @param request
	 * @return
	 *
	 * @author sundar
	 * @date Oct 14, 2022
	 */
	public Map<String, Object> getBrandingDetails(HttpServletRequest request) {
		final String id = AppHttpUtil.getStringParameter(request, ESignConstants.REQUEST_PARAM_ID, null);
		final String encodedSignerId = AppHttpUtil.getStringParameter(request, ESignConstants.REQUEST_PARAM_SIGNER_ID,
				null);

		final IdxFirmESignDocument firmESignDocument = ElasticSearchDAO.getInstance().getDocument(
				AppConstants.ATHENA_INDEX_ID, ObjectConstants.OBJECT_FIRM_ESIGN_DOCUMENT, id,
				IdxFirmESignDocument.class, false);

		final Long firmId = firmESignDocument.getFirmId();
		final Long documentId = firmESignDocument.getDocumentId();

		final Map<String, Object> result = new HashMap<>();

		try {
			Long signerId = null;
			if (encodedSignerId != null) {
				signerId = Long.valueOf(AppEncryptionUtil.dycrypt(encodedSignerId));
			}

			final String[] includeFields = { ESignConstants.SIGN_TYPE, AppConstants.CREATED_BY, ESignConstants.SIGNERS,
					ESignConstants.BID };
			final String[] excludeFields = {};

			final IdxESignDocument idxEsignDocument = ESignatureService.getInstance().getDocument(firmId, documentId,
					includeFields, excludeFields);
			final boolean isValidDoc = ESignatureService.getInstance().validateDocBySignerId(idxEsignDocument,
					signerId);
			if (isValidDoc) {
				// Getting Branding Details
				final IdxFirmBranding firmBranding = ElasticSearchDAO.getInstance().getDocument(firmId,
						IdxFirmBranding.class, ObjectConstants.OBJECT_FIRM_BRANDING, idxEsignDocument.getbId());
				if (firmBranding != null) {
					result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_SUCCESS);
					result.put(AppConstants.RESULT_DATA, firmBranding);
					return result;
				}
			}
		} catch (Exception exception) {
			logger.error(firmId, "SignService:getBrandingDetails:exception:", exception);
		}
		result.put(AppConstants.RESULT_STATUS, AppConstants.RESULT_STATUS_FAILURE);
		return result;
	}
}
