package com.guardcore.engine.py

/**
 * A python-expression syntax validator: the JVM analog of `ast.parse(content, mode="eval")` used by
 * SemanticAnalyzer._check_ast_parsing_risk.
 *
 * Accepts exactly the CPython expression grammar subset eval mode allows (PEP 617 is
 * CPython-internal; the observable contract is accept/reject, which this parser mirrors):
 * conditional expressions, lambda, boolean/not/comparison/arithmetic/unary operators, star
 * expressions in displays, comprehensions, calls, subscripts, attribute access, names, numbers,
 * strings (incl. f-strings and concatenation), tuple/list/set/dict displays, and parenthesized
 * groups. Assignments and statements reject (eval mode).
 */
public object PyAst {
  /** python ast.parse(content, mode="eval") analog: true when the text is one expression. */
  public fun parsesAsExpression(text: String): Boolean {
    return try {
      val p = ExprParser(text)
      p.parseExpression()
      p.atEnd()
    } catch (e: SyntaxErrorSignal) {
      false
    } catch (e: StackOverflowError) {
      false
    }
  }

  private class SyntaxErrorSignal(message: String) : RuntimeException(message)

  private sealed interface Token

  private data class Name(val text: String) : Token

  private data class Num(val text: String) : Token

  private data class Str(val text: String) : Token

  private data class FString(val text: String) : Token

  private data class Op(val symbol: String) : Token

  private class ExprParser(private val src: String) {
    private val tokens: MutableList<Token> = ArrayList()
    private var pos: Int = 0
    private var parenDepth: Int = 0

    init {
      tokenize()
    }

    fun atEnd(): Boolean = pos == tokens.size

    private fun peek(): Token? = tokens.getOrNull(pos)

    private fun peekOp(symbol: String): Boolean {
      val t = peek()
      return t is Op && t.symbol == symbol
    }

    private fun peekName(text: String): Boolean {
      val t = peek()
      return t is Name && t.text == text
    }

    private fun takeOp(symbol: String): Boolean {
      if (peekOp(symbol)) {
        pos++
        return true
      }
      return false
    }

    private fun takeName(text: String): Boolean {
      if (peekName(text)) {
        pos++
        return true
      }
      return false
    }

    private fun expectOp(symbol: String) {
      if (!takeOp(symbol)) throw SyntaxErrorSignal("expected '$symbol'")
    }

    private fun isKeyword(text: String): Boolean =
        text in
            setOf(
                "and",
                "or",
                "not",
                "in",
                "is",
                "if",
                "else",
                "lambda",
                "None",
                "True",
                "False",
                "await",
                "for",
                "async",
                "yield",
            )

    // ---- tokenizer ----

    private fun tokenize() {
      var i = 0
      val n = src.length
      while (i < n) {
        val c = src[i]
        when {
          c.isWhitespace() -> i++
          c == '#' -> {
            while (i < n && src[i] != '\n') i++
          }
          c.isDigit() || (c == '.' && i + 1 < n && src[i + 1].isDigit()) -> {
            val start = i
            var isFloat = false
            if (c == '0' && i + 1 < n && (src[i + 1] == 'x' || src[i + 1] == 'X')) {
              i += 2
              while (i < n && (src[i].isDigit() || src[i] in "abcdefABCDEF_")) i++
            } else {
              while (i < n && (src[i].isDigit() || src[i] == '_')) i++
              if (i < n && src[i] == '.') {
                isFloat = true
                i++
                while (i < n && (src[i].isDigit() || src[i] == '_')) i++
              }
              if (i < n && (src[i] == 'e' || src[i] == 'E')) {
                isFloat = true
                i++
                if (i < n && (src[i] == '+' || src[i] == '-')) i++
                while (i < n && src[i].isDigit()) i++
              }
            }
            if (i < n && src[i].isLetter()) {
              // 1x is invalid; j suffix is a complex literal
              if (src[i] == 'j' || src[i] == 'J') i++ else throw SyntaxErrorSignal("invalid number")
            }
            tokens.add(Num(if (isFloat) "f" else "i"))
          }
          c == '"' || c == '\'' -> {
            i = readString(i)
            tokens.add(Str("s"))
          }
          c == 'f' || c == 'F' -> {
            if (i + 1 < n && (src[i + 1] == '"' || src[i + 1] == '\'')) {
              i = readString(i + 1)
              tokens.add(FString("f"))
            } else {
              i = readName(i)
            }
          }
          c.isLetter() || c == '_' -> i = readName(i)
          else -> {
            val two = if (i + 1 < n) src.substring(i, i + 2) else ""
            val three = if (i + 2 < n) src.substring(i, i + 3) else ""
            when {
              three == "**=" || three == "//=" || three == ">>=" || three == "<<=" ->
                  i += 0 // aug ops reject in eval anyway; tokenize as parts
              two == "**" ||
                  two == "//" ||
                  two == "<<" ||
                  two == ">>" ||
                  two == "<=" ||
                  two == ">=" ||
                  two == "==" ||
                  two == "!=" ||
                  two == "->" ||
                  two == ":=" -> {
                tokens.add(Op(two))
                i += 2
              }
              else -> {
                tokens.add(Op(c.toString()))
                i++
              }
            }
          }
        }
      }
    }

    private fun readString(start: Int): Int {
      var i = start
      val n = src.length
      val quote = src[i]
      var triple = false
      if (i + 2 < n && src[i + 1] == quote && src[i + 2] == quote) {
        triple = true
        i += 3
      } else {
        i++
      }
      while (i < n) {
        val c = src[i]
        if (c == '\\' && i + 1 < n) {
          i += 2
          continue
        }
        if (triple) {
          if (c == quote && i + 2 < n && src[i + 1] == quote && src[i + 2] == quote) {
            return i + 3
          }
          i++
        } else {
          if (c == quote) return i + 1
          if (c == '\n') throw SyntaxErrorSignal("unterminated string")
          i++
        }
      }
      throw SyntaxErrorSignal("unterminated string")
    }

    private fun readName(start: Int): Int {
      var i = start
      val n = src.length
      while (i < n && (src[i].isLetterOrDigit() || src[i] == '_')) i++
      tokens.add(Name(src.substring(start, i)))
      return i
    }

    // ---- grammar (precedence climbing, CPython order) ----

    fun parseExpression() {
      if (takeName("lambda")) {
        parseLambdaBody()
        return
      }
      parseConditional()
    }

    private fun parseLambdaBody() {
      // lambda params: ':' expr
      while (!peekOp(":")) {
        val t = peek() ?: throw SyntaxErrorSignal("lambda: missing ':'")
        if (t is Name && !isKeyword(t.text)) {
          pos++
          if (takeOp(":")) break
          if (takeOp(",")) continue
          if (takeOp("=")) {
            parseExpression()
            if (takeOp(",")) continue
            expectOp(":")
            break
          }
          if (takeOp("*") || (takeOp("*"))) {
            continue
          }
          throw SyntaxErrorSignal("lambda: bad parameter")
        }
        if (t is Op && (t.symbol == "*" || t.symbol == "**")) {
          pos++
          continue
        }
        throw SyntaxErrorSignal("lambda: bad parameter")
      }
      parseExpression()
    }

    private fun parseConditional() {
      if (peekName("await")) {
        pos++
        parseUnary()
      } else {
        parseOr()
      }
      if (takeName("if")) {
        parseOr()
        expectNameElse()
      }
    }

    private fun expectNameElse() {
      if (!takeName("else")) throw SyntaxErrorSignal("expected else")
      parseExpression()
    }

    private fun parseOr() {
      parseAnd()
      while (takeName("or")) parseAnd()
    }

    private fun parseAnd() {
      parseNot()
      while (takeName("and")) parseNot()
    }

    private fun parseNot() {
      if (takeName("not")) {
        parseNot()
        return
      }
      parseComparison()
    }

    private fun parseComparison() {
      parseBitOr()
      while (true) {
        when {
          takeOp("==") ||
              takeOp("!=") ||
              takeOp("<=") ||
              takeOp(">=") ||
              takeOp("<") ||
              takeOp(">") -> parseBitOr()
          peekName("in") -> {
            pos++
            parseBitOr()
          }
          peekName("not") -> {
            pos++
            if (!takeName("in")) throw SyntaxErrorSignal("expected in")
            parseBitOr()
          }
          peekName("is") -> {
            pos++
            takeName("not")
            parseBitOr()
          }
          else -> return
        }
      }
    }

    private fun parseBitOr() {
      parseBitXor()
      while (takeOp("|")) parseBitXor()
    }

    private fun parseBitXor() {
      parseBitAnd()
      while (takeOp("^")) parseBitAnd()
    }

    private fun parseBitAnd() {
      parseShift()
      while (takeOp("&")) parseShift()
    }

    private fun parseShift() {
      parseArith()
      while (takeOp("<<") || takeOp(">>")) parseArith()
    }

    private fun parseArith() {
      parseTerm()
      while (takeOp("+") || takeOp("-")) parseTerm()
    }

    private fun parseTerm() {
      parseUnary()
      while (takeOp("*") || takeOp("/") || takeOp("//") || takeOp("%") || takeOp("@")) parseUnary()
    }

    private fun parseUnary() {
      if (takeOp("-") || takeOp("+") || takeOp("~")) {
        parseUnary()
        return
      }
      parsePower()
    }

    private fun parsePower() {
      parsePostfix()
      if (takeOp("**")) {
        parseUnary()
      }
    }

    private fun parsePostfix() {
      parseAtom()
      while (true) {
        when {
          takeOp(".") -> {
            val t = peek() ?: throw SyntaxErrorSignal("attribute: missing name")
            if (t !is Name || isKeyword(t.text)) {
              if (t is Name && (t.text == "None" || t.text == "True" || t.text == "False")) {
                pos++
              } else {
                throw SyntaxErrorSignal("attribute: invalid name")
              }
            } else {
              pos++
            }
          }
          takeOp("(") -> parseCallArgs()
          takeOp("[") -> {
            parenDepth++
            parseSubscriptList()
            parenDepth--
            expectOp("]")
          }
          else -> return
        }
      }
    }

    private fun parseCallArgs() {
      parenDepth++
      if (takeOp(")")) {
        parenDepth--
        return
      }
      while (true) {
        if (takeOp("*") || takeOp("**")) {
          parseExpression()
        } else {
          val before = pos
          parseExpression()
          if (takeOp(":=")) {
            // walrus: NAME := expr - parseExpression already consumed name
          } else if (pos == before) {
            throw SyntaxErrorSignal("call: empty argument")
          } else if (takeOp("=")) {
            parseExpression()
          } else if (peekOp(":")) {
            // annotation in call is invalid
            throw SyntaxErrorSignal("call: unexpected annotation")
          }
        }
        if (takeOp(",")) {
          if (takeOp(")")) {
            parenDepth--
            return
          }
          continue
        }
        parenDepth--
        expectOp(")")
        return
      }
    }

    private fun parseSubscriptList() {
      if (takeOp("*")) {
        parseExpression()
      } else {
        parseExpression()
        if (takeOp(":")) {
          // slice
          parseExpression()
          if (takeOp(":")) {
            parseExpression()
          }
        }
      }
      while (takeOp(",")) {
        if (peekOp("]")) return
        if (takeOp("*")) {
          parseExpression()
          continue
        }
        parseExpression()
        if (takeOp(":")) {
          parseExpression()
          if (takeOp(":")) {
            parseExpression()
          }
        }
      }
    }

    private fun parseAtom() {
      val t = peek() ?: throw SyntaxErrorSignal("unexpected end of expression")
      when (t) {
        is Name -> {
          pos++
          when (t.text) {
            "None",
            "True",
            "False" -> {}
            "lambda" -> parseLambdaBody()
            "not" -> throw SyntaxErrorSignal("atom: not")
            else -> {}
          }
        }
        is Num -> pos++
        is Str,
        is FString -> pos++
        is Op -> {
          when (t.symbol) {
            "(" -> {
              pos++
              parenDepth++
              parseParenBody()
              parenDepth--
            }
            "[" -> {
              pos++
              parenDepth++
              parseListBody()
              parenDepth--
            }
            "{" -> {
              pos++
              parenDepth++
              parseBraceBody()
              parenDepth--
            }
            else -> throw SyntaxErrorSignal("unexpected token '${t.symbol}'")
          }
        }
      }
    }

    private fun parseParenBody() {
      if (takeOp(")")) return
      if (takeName("yield")) throw SyntaxErrorSignal("yield not allowed in eval mode")
      if (takeOp("*")) {
        parseExpression()
      } else {
        parseExpression()
        if (peekOp(":=")) {
          pos++
          parseExpression()
        }
      }
      while (takeOp(",")) {
        if (takeOp(")")) return
        if (takeOp("*")) {
          parseExpression()
          continue
        }
        parseExpression()
        if (peekOp(":=")) {
          pos++
          parseExpression()
        }
      }
      expectOp(")")
    }

    private fun parseListBody() {
      if (takeOp("]")) return
      while (true) {
        if (takeOp("*")) {
          parseExpression()
        } else {
          parseExpression()
        }
        if (takeName("for")) {
          parseComprehension()
          expectOp("]")
          return
        }
        if (takeOp(",")) {
          if (takeOp("]")) return
          continue
        }
        expectOp("]")
        return
      }
    }

    private fun parseBraceBody() {
      if (takeOp("}")) return
      if (takeOp("**")) {
        // dict unpacking
        parseExpression()
      } else {
        parseExpression()
        if (takeOp(":")) {
          parseExpression()
        }
      }
      if (takeName("for")) {
        parseComprehension()
        expectOp("}")
        return
      }
      while (takeOp(",")) {
        if (takeOp("}")) return
        if (takeOp("**")) {
          parseExpression()
        } else {
          parseExpression()
          if (takeOp(":")) parseExpression()
        }
        if (takeName("for")) {
          parseComprehension()
          expectOp("}")
          return
        }
      }
      expectOp("}")
    }

    private fun parseComprehension() {
      // for target in or_test [iterators]
      parseComprehensionTarget()
      if (!takeName("in")) throw SyntaxErrorSignal("comprehension: expected in")
      parseOr()
      if (takeName("if")) {
        parseOrNoCond()
      }
      while (takeName("for") || takeName("if")) {
        if (peekOp("for") || !atEnd()) {
          if (peekOp("if")) {
            pos++
            parseOrNoCond()
          } else {
            parseComprehensionTarget()
            if (!takeName("in")) throw SyntaxErrorSignal("comprehension: expected in")
            parseOr()
          }
        }
      }
    }

    private fun parseOrNoCond() {
      parseOr()
    }

    private fun parseComprehensionTarget() {
      // NAME [.NAME] or (target) or [target, target]
      if (takeOp("(")) {
        parseComprehensionTarget()
        if (!takeOp(")")) {
          while (takeOp(",")) {
            if (takeOp(")")) return
            parseComprehensionTarget()
          }
          expectOp(")")
        }
        return
      }
      if (takeOp("[")) {
        while (!peekOp("]")) {
          parseComprehensionTarget()
          if (!takeOp(",")) break
        }
        expectOp("]")
        return
      }
      if (takeOp("*")) {
        parseComprehensionTarget()
        return
      }
      val t = peek() ?: throw SyntaxErrorSignal("comprehension: missing target")
      if (t is Name && !isKeyword(t.text)) {
        pos++
        while (takeOp(".")) {
          val a = peek() ?: throw SyntaxErrorSignal("comprehension: bad attribute")
          if (a is Name) pos++ else throw SyntaxErrorSignal("comprehension: bad attribute")
        }
        return
      }
      throw SyntaxErrorSignal("comprehension: invalid target")
    }
  }
}
