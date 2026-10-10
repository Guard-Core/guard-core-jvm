package com.guardcore.engine.suspatterns

import com.guardcore.engine.detection.ContentPreprocessor
import com.guardcore.engine.detection.PatternCompiler
import com.guardcore.engine.detection.PatternValidationCache
import com.guardcore.engine.detection.PerformanceMonitor
import com.guardcore.engine.detection.SemanticAnalyzer
import com.guardcore.engine.py.PyRe
import java.nio.file.Paths

/**
 * Detection state bundle and the HTML event-handler alternation table.
 *
 * Port of guard_core/handlers/_suspatterns_state.py.
 */
public class DetectionState(
    public val compiler: PatternCompiler?,
    public val preprocessor: ContentPreprocessor?,
    public val semanticAnalyzer: SemanticAnalyzer?,
    public val performanceMonitor: PerformanceMonitor?,
    public val semanticThreshold: Double,
    public val threatScoreThreshold: Double,
)

public val LEGACY_DETECTION_STATE: DetectionState =
    DetectionState(
        compiler = null,
        preprocessor = null,
        semanticAnalyzer = null,
        performanceMonitor = null,
        semanticThreshold = 0.7,
        threatScoreThreshold = 1.0,
    )

/** The config interface the enhanced state builder consumes (the W1 facade SecurityConfig). */
public interface DetectionConfigView {
  public val detectionCompilerTimeout: Double
  public val detectionMaxTrackedPatterns: Int
  public val detectionMaxContentLength: Int
  public val detectionPreserveAttackPatterns: Boolean
  public val detectionAnomalyThreshold: Double
  public val detectionSlowPatternThreshold: Double
  public val detectionMonitorHistorySize: Int
  public val detectionAnomalyEmissionCooldown: Double
  public val detectionMinSamplesForAnomaly: Int
  public val detectionSemanticThreshold: Double
  public val detectionThreatScoreThreshold: Double
  public val detectionMaxBodyInspectBytes: Int
  public val detectionPatternValidationCachePath: String?
}

/** _supports_enhanced_config: always true for the typed JVM config view. */
public fun supportsEnhancedConfig(config: Any?): Boolean = config is DetectionConfigView

/** _build_enhanced_detection_state. */
public fun buildEnhancedDetectionState(config: DetectionConfigView): DetectionState {
  val cachePath = config.detectionPatternValidationCachePath
  val validationCache =
      if (cachePath != null) {
        PatternValidationCache(Paths.get(cachePath), "4.3.2")
      } else {
        null
      }
  return DetectionState(
      compiler =
          PatternCompiler(
              defaultTimeout = config.detectionCompilerTimeout,
              maxCacheSize = config.detectionMaxTrackedPatterns,
              validationCache = validationCache,
          ),
      preprocessor =
          ContentPreprocessor(
              maxContentLength = config.detectionMaxContentLength,
              preserveAttackPatterns = config.detectionPreserveAttackPatterns,
              maxFullScanBytes = config.detectionMaxBodyInspectBytes,
          ),
      semanticAnalyzer = SemanticAnalyzer(),
      performanceMonitor =
          PerformanceMonitor(
              anomalyThreshold = config.detectionAnomalyThreshold,
              slowPatternThreshold = config.detectionSlowPatternThreshold,
              historySize = config.detectionMonitorHistorySize,
              maxTrackedPatterns = config.detectionMaxTrackedPatterns,
              anomalyEmissionCooldown = config.detectionAnomalyEmissionCooldown,
              minSamplesForAnomaly = config.detectionMinSamplesForAnomaly,
          ),
      semanticThreshold = config.detectionSemanticThreshold,
      threatScoreThreshold = config.detectionThreatScoreThreshold,
  )
}

/** The HTML event handler attribute set (re-derived 2026-08-20; see python provenance). */
public val HTML_EVENT_HANDLER_ATTRS: Set<String> =
    setOf(
        "onabort",
        "onactivate",
        "onafterprint",
        "onafterscriptexecute",
        "onafterupdate",
        "onanimationcancel",
        "onanimationend",
        "onanimationiteration",
        "onanimationstart",
        "onauxclick",
        "onbeforeactivate",
        "onbeforecopy",
        "onbeforecut",
        "onbeforedeactivate",
        "onbeforeeditfocus",
        "onbeforeinput",
        "onbeforematch",
        "onbeforepaste",
        "onbeforeprint",
        "onbeforescriptexecute",
        "onbeforetoggle",
        "onbeforeunload",
        "onbeforeupdate",
        "onbegin",
        "onblur",
        "onbounce",
        "oncancel",
        "oncanplay",
        "oncanplaythrough",
        "oncellchange",
        "onchange",
        "onclick",
        "onclose",
        "oncommand",
        "oncontentvisibilityautostatechange",
        "oncontextlost",
        "oncontextmenu",
        "oncontextrestored",
        "oncontrolselect",
        "oncopy",
        "oncuechange",
        "oncut",
        "ondataavailable",
        "ondatasetchanged",
        "ondatasetcomplete",
        "ondblclick",
        "ondeactivate",
        "ondevicemotion",
        "ondeviceorientation",
        "ondrag",
        "ondragdrop",
        "ondragend",
        "ondragenter",
        "ondragexit",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "ondurationchange",
        "onemptied",
        "onend",
        "onended",
        "onerror",
        "onerrorupdate",
        "onfilterchange",
        "onfinish",
        "onfocus",
        "onfocusin",
        "onfocusout",
        "onformdata",
        "onfullscreenchange",
        "ongesturechange",
        "ongestureend",
        "ongesturestart",
        "ongotpointercapture",
        "onhashchange",
        "onhelp",
        "oninput",
        "oninvalid",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onlanguagechange",
        "onlayoutcomplete",
        "onload",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onlocation",
        "onlosecapture",
        "onlostpointercapture",
        "onmediacomplete",
        "onmediaerror",
        "onmessage",
        "onmessageerror",
        "onmousedown",
        "onmouseenter",
        "onmouseleave",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onmousewheel",
        "onmove",
        "onmoveend",
        "onmovestart",
        "onmozfullscreenchange",
        "onoffline",
        "ononline",
        "onoutofsync",
        "onpagehide",
        "onpagereveal",
        "onpageshow",
        "onpageswap",
        "onpaste",
        "onpause",
        "onplay",
        "onplaying",
        "onpointercancel",
        "onpointerdown",
        "onpointerenter",
        "onpointerleave",
        "onpointermove",
        "onpointerout",
        "onpointerover",
        "onpointerrawupdate",
        "onpointerup",
        "onpopstate",
        "onprogress",
        "onpromptaction",
        "onpromptdismiss",
        "onpropertychange",
        "onratechange",
        "onreadystatechange",
        "onredo",
        "onrejectionhandled",
        "onrepeat",
        "onreset",
        "onresize",
        "onresizeend",
        "onresizestart",
        "onresume",
        "onreverse",
        "onrowdelete",
        "onrowexit",
        "onrowinserted",
        "onrowsenter",
        "onscroll",
        "onscrollend",
        "onscrollsnapchange",
        "onscrollsnapchanging",
        "onsearch",
        "onsecuritypolicyviolation",
        "onseek",
        "onseeked",
        "onseeking",
        "onselect",
        "onselectionchange",
        "onselectstart",
        "onslotchange",
        "onstalled",
        "onstart",
        "onstop",
        "onstorage",
        "onsubmit",
        "onsuspend",
        "onsyncrestored",
        "ontimeerror",
        "ontimeupdate",
        "ontoggle",
        "ontouchcancel",
        "ontouchend",
        "ontouchmove",
        "ontouchstart",
        "ontrackchange",
        "ontransitioncancel",
        "ontransitionend",
        "ontransitionrun",
        "ontransitionstart",
        "onundo",
        "onunhandledrejection",
        "onunload",
        "onurlflip",
        "onvalidationstatuschange",
        "onvolumechange",
        "onwaiting",
        "onwebkitanimationend",
        "onwebkitanimationiteration",
        "onwebkitanimationstart",
        "onwebkitfullscreenchange",
        "onwebkitmouseforcechanged",
        "onwebkitmouseforcedown",
        "onwebkitmouseforceup",
        "onwebkitmouseforcewillbegin",
        "onwebkitneedkey",
        "onwebkitplaybacktargetavailabilitychanged",
        "onwebkitpresentationmodechanged",
        "onwebkittransitionend",
        "onwebkitwillrevealbottom",
        "onwheel",
    )

/** _HTML_EVENT_HANDLER_ALTERNATION: longest-first, then lexicographic. */
public val HTML_EVENT_HANDLER_ALTERNATION: String =
    HTML_EVENT_HANDLER_ATTRS.sortedWith(compareByDescending<String> { it.length }.thenBy { it })
        .joinToString("|") { PyRe.escapeSource(it) }
