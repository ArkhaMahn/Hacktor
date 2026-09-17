package org.zaproxy.zap.extension.hacktor;

import org.parosproxy.paros.network.HttpMessage;

/**
 * The outcome of sending a single bypass technique. Carries the full
 * HttpMessage so the UI can display complete request/response details.
 */
public final class Result {

    private final Technique technique;
    private final String path;
    private final Technique.Verdict verdict;
    private final int baselineStatus;
    private final int status;
    private final int baselineLength;
    private final int length;
    private final boolean similarLength;
    private final String bodySample;
    private final HttpMessage message;
    /** ISO-8601 timestamp of when the request was sent, or "-" when unknown. */
    private final String reqTime;
    /** ISO-8601 timestamp of when the response was received, or "-" when unknown. */
    private final String resTime;

    public Result(
            Technique technique,
            String path,
            Technique.Verdict verdict,
            int baselineStatus,
            int status,
            int baselineLength,
            int length,
            boolean similarLength,
            String bodySample,
            HttpMessage message) {
        this(technique, path, verdict, baselineStatus, status, baselineLength, length,
            similarLength, bodySample, message, "-", "-");
    }

    public Result(
            Technique technique,
            String path,
            Technique.Verdict verdict,
            int baselineStatus,
            int status,
            int baselineLength,
            int length,
            boolean similarLength,
            String bodySample,
            HttpMessage message,
            String reqTime,
            String resTime) {
        this.technique = technique;
        this.path = path;
        this.verdict = verdict;
        this.baselineStatus = baselineStatus;
        this.status = status;
        this.baselineLength = baselineLength;
        this.length = length;
        this.similarLength = similarLength;
        this.bodySample = bodySample;
        this.message = message;
        this.reqTime = reqTime;
        this.resTime = resTime;
    }

    public Technique getTechnique() { return technique; }
    public String getFamily() { return technique.getFamily(); }
    public String getLabel() { return technique.getLabel(); }
    public String getDescription() { return technique.getDescription(); }
    public String getPath() { return path; }
    public Technique.Verdict getVerdict() { return verdict; }
    public int getBaselineStatus() { return baselineStatus; }
    public int getStatus() { return status; }
    public int getBaselineLength() { return baselineLength; }
    public int getLength() { return length; }
    public boolean isSimilarLength() { return similarLength; }
    public String getBodySample() { return bodySample; }
    public HttpMessage getMessage() { return message; }
    public String getReqTime() { return reqTime; }
    public String getResTime() { return resTime; }
}
