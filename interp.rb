require("minruby")

def inv(flg)
  if flg
    false
  else
    true
  end
end

def bool(v)
  inv(inv(v))
end

def fullslice(str)
  i = 0
  while str[i]
    i = i + 1
  end
  [str, 0, i]
end

def slice(slc, start, len)
  [slc[0], slc[1] + start, len]
end
def sget(slc, i)
  slc[0][slc[1] + i]
end
def slen(slc)
  slc[2]
end
def sconsume(slc, len)
  [slc[0], slc[1] + len, slc[2] - len]
end

def r_tk(ret)
  ret && ret[0]
end

def r_slc(ret)
  ret && ret[1]
end

def to_i(chr)
  case chr
  when "0"
    0
  when "1"
    1
  when "2"
    2
  when "3"
    3
  when "4"
    4
  when "5"
    5
  when "6"
    6
  when "7"
    7
  when "8"
    8
  when "9"
    9
  else
    nil
  end
end

def skip_wsnl(slc)
  i = 0
  len = slen(slc)
  nl = "
"
  while i < len && (sget(slc, i) == " " || sget(slc, i) == nl)
    i = i + 1
  end
  sconsume(slc, i)
end

def expect(bas, pat)
  bas_len = slen(bas)
  pat_len = slen(pat)
  if bas_len >= pat_len
    i = 0
    while i < pat_len && sget(bas, i) == sget(pat, i)
      i = i + 1
    end
    if i == pat_len
      sconsume(bas, i)
    else
      nil
    end
  else
    nil
  end
end

def tk_num(slc)
  i = 0
  len = slen(slc)
  n = 0
  while i < len && digit = to_i(sget(slc, i))
    n = n * 10 + digit
    i = i + 1
  end
  if i == 0
    nil
  else
    [["lit", n], sconsume(slc, i)]
  end
end

def tk_str(slc)
  chr = sget(slc, 0)
  if "!" < chr && chr < "#"
    buf = ""
    i = 0
    while (slc = sconsume(slc, 1)) && (chr = sget(slc, 0)) && inv("!" < chr && chr < "#")
      buf = buf + chr
    end
    slc = sconsume(slc, 1)
    [["lit", buf], slc]
  else
    nil
  end
end

def tk_bool(slc)
  slc2 = nil
  case true
  when bool(slc2 = expect(slc, ["true", 0, 4]))
    [["lit", true], slc2]
  when bool(slc2 = expect(slc, ["false", 0, 5]))
    [["lit", false], slc2]
  else
    nil
  end
end

def tk_ident(slc)
  fchr = sget(slc, 0)
  if (fchr == "_") || ("A" <= fchr && fchr <= "Z") || ("a" <= fchr && fchr <= "z")
    ident = fchr
    slc = sconsume(slc, 1)
    while slen(slc) > 0 && (chr = sget(slc, 0)) && ((chr == "_") || (chr == "?") || ("A" <= chr && chr <= "Z") || ("a" <= chr && chr <= "z") || ("0" <= chr && chr <= "9"))
      ident = ident + chr
      slc = sconsume(slc, 1)
    end
    case ident
    when "if"
      [["kword", ident], slc]
    when "else"
      [["kword", ident], slc]
    when "end"
      [["kword", ident], slc]
    when "while"
      [["kword", ident], slc]
    when "def"
      [["kword", ident], slc]
    when "case"
      [["kword", ident], slc]
    when "when"
      [["kword", ident], slc]
    else
      [["ident", ident], slc]
    end
  else
    nil
  end
end

def tk_lit(slc)
  ret = nil
  case true
  when bool(ret = tk_num(slc))
    ret
  when bool(ret = tk_str(slc))
    ret
  when bool(ret = tk_bool(slc))
    ret
  else
    nil
  end
end

def tk_simple(slc, tk, str, len)
  ret = expect(slc, [str, 0, len])
  if ret
    [[tk], ret]
  else
    nil
  end
end

def tk_comma(slc)
  tk_simple(slc, ",", ",", 1)
end

def tk_pareno(slc)
  tk_simple(slc, "(", "(", 1)
end

def tk_parenc(slc)
  tk_simple(slc, ")", ")", 1)
end

def tk_plus(slc)
  tk_simple(slc, "+", "+", 1)
end
def tk_minus(slc)
  tk_simple(slc, "-", "-", 1)
end
def tk_aster(slc)
  tk_simple(slc, "*", "*", 1)
end
def tk_slash(slc)
  tk_simple(slc, "/", "/", 1)
end
def tk_percent(slc)
  tk_simple(slc, "%", "%", 1)
end
def tk_angleo(slc)
  tk_simple(slc, "<", "<", 1)
end
def tk_anglec(slc)
  tk_simple(slc, ">", ">", 1)
end
def tk_squareo(slc)
  tk_simple(slc, "[", "[", 1)
end
def tk_squarec(slc)
  tk_simple(slc, "]", "]", 1)
end
def tk_curlyo(slc)
  tk_simple(slc, "{", "{", 1)
end
def tk_curlyc(slc)
  tk_simple(slc, "}", "}", 1)
end
def tk_angleoeq(slc)
  tk_simple(slc, "<=", "<=", 2)
end
def tk_angleceq(slc)
  tk_simple(slc, ">=", ">=", 2)
end
def tk_eqeq(slc)
  tk_simple(slc, "==", "==", 2)
end
def tk_bangeq(slc)
  tk_simple(slc, "!=", "!=", 2)
end
def tk_ampamp(slc)
  tk_simple(slc, "&&", "&&", 2)
end
def tk_pipepipe(slc)
  tk_simple(slc, "||", "||", 2)
end
def tk_eqanglec(slc)
  tk_simple(slc, "=>", "=>", 2)
end
def tk_eq(slc)
  tk_simple(slc, "=", "=", 1)
end

def tk_expect(tslc, tk)
  ret = sget(tslc, 0)
  if ret && ret[0] == tk
    [ret, sconsume(tslc, 1)]
  else
    nil
  end
end

def tokenize(slc)
  slc = skip_wsnl(slc)
  tks = []
  i = 0
  while slen(slc) > 0
    ret = tk_lit(slc) || tk_ident(slc) || tk_comma(slc) || tk_pareno(slc) || tk_parenc(slc) || tk_plus(slc) || tk_minus(slc) || tk_aster(slc) || tk_slash(slc) || tk_percent(slc) || tk_angleoeq(slc) || tk_angleceq(slc) || tk_squareo(slc) || tk_squarec(slc) || tk_curlyo(slc) || tk_curlyc(slc) || tk_eqeq(slc) || tk_bangeq(slc) || tk_ampamp(slc) || tk_pipepipe(slc) || tk_eqanglec(slc) || tk_eq(slc) || tk_angleo(slc) || tk_anglec(slc)
    if ret == nil
      p(slc)
      p(tks)
      raise("unknown token")
    end
    slc = ret[1]
    tks[i] = ret[0]
    i = i + 1
    slc = skip_wsnl(slc)
  end
  [tks, 0, i]
end

def parse_func_def(tslc)
  ret = tk_expect(tslc, "kword")
  if ret && r_tk(ret)[1] == "def"
    tslc = r_slc(ret)
    ret = tk_expect(tslc, "ident")
    if ret
      tslc = r_slc(ret)
      fname = r_tk(ret)[1]
      args = []
      i = 0
      ret = tk_expect(tslc, "(")
      if ret
        tslc = r_slc(ret)
        ret = tk_expect(tslc, ")")
        if ret == nil
          failed = false
          done = false
          while done == false && failed == false
            ret = tk_expect(tslc, "ident")
            if ret
              tslc = r_slc(ret)
              args[i] = r_tk(ret)[1]
              i = i + 1
              ret = tk_expect(tslc, ",")
              if ret == nil
                done = true
              else
                tslc = r_slc(ret)
              end
            else
              failed = true
            end
          end
          ret = tk_expect(tslc, ")")
        end
        if ret
          tslc = r_slc(ret)
          ret = parse_stmts(tslc)
          if ret
            tslc = r_slc(ret)
            bdy = r_tk(ret)
            ret = tk_expect(tslc, "kword")
            if ret && r_tk(ret)[1] == "end"
              tslc = r_slc(ret)
              [["func_def", fname, args, bdy], tslc]
            end
          end
        end
      end
    end
  end
end

def parse_func_call(tslc)
  ret = tk_expect(tslc, "ident")
  if ret
    tk = ["func_call", ret[0][1]]
    i = 2
    tslc = r_slc(ret)
    ret = tk_expect(tslc, "(")
    if ret
      tslc = r_slc(ret)
      ret = tk_expect(tslc, ")")
      if ret
        [tk, r_slc(ret)]
      else
        failed = false
        done = false
        while done == false && failed == false
          ret = parse_assign_expr(tslc)
          if ret
            tslc = r_slc(ret)
            tk[i] = ret[0]
            i = i + 1
            ret = tk_expect(tslc, ",")
            if ret == nil
              done = true
            else
              tslc = r_slc(ret)
            end
          else
            failed = true
          end
        end
        ret = tk_expect(tslc, ")")
        if ret
          [tk, r_slc(ret)]
        end
      end
    end
  end
end

def parse_var_ref(tslc)
  ret = tk_expect(tslc, "ident")
  if ret
    [["var_ref", r_tk(ret)[1]], r_slc(ret)]
  end
end

def parse_ary_new(tslc)
  ret = tk_expect(tslc, "[")
  if ret
    tslc = r_slc(ret)
    tk = ["ary_new"]
    i = 1
    ret = tk_expect(tslc, "]")
    if ret
      tslc = r_slc(ret)
      [tk, tslc]
    else
      failed = false
      done = false
      while done == false && failed == false
        ret = parse_assign_expr(tslc)
        if ret
          tslc = r_slc(ret)
          tk[i] = ret[0]
          i = i + 1
          ret = tk_expect(tslc, ",")
          if ret == nil
            done = true
          else
            tslc = r_slc(ret)
          end
        else
          failed = true
        end
      end
      ret = tk_expect(tslc, "]")
      if ret
        [tk, r_slc(ret)]
      end
    end
  end
end

def parse_hash_pair(tslc)
  ret = parse_assign_expr(tslc)
  if ret
    tslc = r_slc(ret)
    key = r_tk(ret)
    ret = tk_expect(tslc, "=>")
    if ret
      tslc = r_slc(ret)
      ret = parse_assign_expr(tslc)
      if ret
        tslc = r_slc(ret)
        value = r_tk(ret)
        [[key, value], tslc]
      end
    end
  end
end

def parse_hash_new(tslc)
  ret = tk_expect(tslc, "{")
  if ret
    tslc = r_slc(ret)
    tk = ["hash_new"]
    i = 1
    ret = tk_expect(tslc, "}")
    if ret
      tslc = r_slc(ret)
      [tk, tslc]
    else
      failed = false
      done = false
      while done == false && failed == false
        ret = parse_hash_pair(tslc)
        if ret
          tslc = r_slc(ret)
          pair = r_tk(ret)
          tk[i] = pair[0]
          tk[i + 1] = pair[1]
          i = i + 2
          ret = tk_expect(tslc, ",")
          if ret == nil
            done = true
          else
            tslc = r_slc(ret)
          end
        else
          failed = true
        end
      end
      ret = tk_expect(tslc, "}")
      if ret
        [tk, r_slc(ret)]
      end
    end
  end
end

def parse_paren(tslc)
  ret = tk_expect(tslc, "(")
  if ret
    tslc = r_slc(ret)
    ret = parse_assign_expr(tslc)
    if ret
      tslc = r_slc(ret)
      ex = ret[0]
      ret = tk_expect(tslc, ")")
      if ret
        [ex, r_slc(ret)]
      end
    end
  end
end

def parse_atom(tslc)
  case true
  when bool(ret = tk_expect(tslc, "lit"))
    ret
  when bool(ret = parse_func_call(tslc))
    ret
  when bool(ret = parse_var_ref(tslc))
    ret
  when bool(ret = parse_paren(tslc))
    ret
  when bool(ret = parse_if(tslc))
    ret
  when bool(ret = parse_case(tslc))
    ret
  when bool(ret = parse_while(tslc))
    ret
  when bool(ret = parse_ary_new(tslc))
    ret
  when bool(ret = parse_hash_new(tslc))
    ret
  end
end

def parse_fact(tslc)
  ret = parse_atom(tslc)
  if ret
    tslc = r_slc(ret)
    root = r_tk(ret)
    while (ret = parse_ary_ref_idx(tslc))
      tslc = r_slc(ret)
      root = ["ary_ref", root, r_tk(ret)]
    end
    [root, tslc]
  end
end

def parse_term(tslc)
  ret = parse_fact(tslc)
  if ret
    tslc = r_slc(ret)
    ltk = r_tk(ret)
    while (ret2 = tk_expect(tslc, "*") || tk_expect(tslc, "/") || tk_expect(tslc, "%"))
      tslc = r_slc(ret2)
      op = r_tk(ret2)
      ret = parse_fact(tslc)
      if ret
        tslc = r_slc(ret)
        rtk = r_tk(ret)
        ltk = [op[0], ltk, rtk]
      end
    end
    [ltk, tslc]
  end
end

def parse_var_assign(tslc)
  ret = tk_expect(tslc, "ident")
  if ret
    tslc = r_slc(ret)
    ltk = r_tk(ret)
    rtk = nil
    while (ret2 = tk_expect(tslc, "="))
      tslc = r_slc(ret2)
      op = r_tk(ret2)
      ret = parse_assign_expr(tslc)
      if ret
        tslc = r_slc(ret)
        rtk = r_tk(ret)
        rtk = ["var_assign", ltk[1], rtk]
      end
    end
    if rtk
      [rtk, tslc]
    else
      nil
    end
  end
end

def parse_ary_assign(tslc)
  ret = parse_atom(tslc)
  if ret
    tslc = r_slc(ret)
    root = r_tk(ret)
    while (ret = parse_ary_ref_idx(tslc))
      tslc = r_slc(ret)
      root = ["ary_ref", root, r_tk(ret)]
    end

    if root[0] == "ary_ref"
      ret = tk_expect(tslc, "=")
      if ret
        tslc = r_slc(ret)
        ret = parse_assign_expr(tslc)
        if ret
          tslc = r_slc(ret)
          rhe = r_tk(ret)
          root[0] = "ary_assign"
          root[3] = rhe
          [root, tslc]
        end
      end
    end
  end
end

def parse_if(tslc)
  ret = tk_expect(tslc, "kword")
  if ret && r_tk(ret)[1] == "if"
    tslc = r_slc(ret)
    ret = parse_assign_expr(tslc)
    cnd = r_tk(ret)
    if ret
      tslc = r_slc(ret)
      ret = parse_stmts(tslc)
      thn = r_tk(ret)
      if ret
        tslc = r_slc(ret)
        ret = tk_expect(tslc, "kword")
        if ret
          tslc = r_slc(ret)
          els = ["lit", nil]
          if r_tk(ret)[1] == "else"
            ret = parse_stmts(tslc)
            els = r_tk(ret)
            tslc = r_slc(ret)
            ret = tk_expect(tslc, "kword")
          end
          if ret && r_tk(ret)[1] == "end"
            [["if", cnd, thn, els], r_slc(ret)]
          end
        end
      end
    end
  end
end

def parse_when(tslc)
  ret = tk_expect(tslc, "kword")
  if ret && r_tk(ret)[1] == "when"
    tslc = r_slc(ret)
    ret = parse_assign_expr(tslc)
    if ret
      tslc = r_slc(ret)
      rcnd = r_tk(ret)
      ret = parse_stmts(tslc)
      if ret
        tslc = r_slc(ret)
        bdy = r_tk(ret)
        [[rcnd, bdy], tslc]
      end
    end
  end
end

def parse_else(tslc)
  ret = tk_expect(tslc, "kword")
  if ret && r_tk(ret)[1] == "else"
    tslc = r_slc(ret)
    ret = parse_stmts(tslc)
    if ret
      tslc = r_slc(ret)
      bdy = r_tk(ret)
      [bdy, tslc]
    end
  end
end

def parse_case(tslc)
  ret = tk_expect(tslc, "kword")
  if ret && r_tk(ret)[1] == "case"
    tslc = r_slc(ret)
    ret = parse_assign_expr(tslc)
    if ret
      tslc = r_slc(ret)
      lcnd = r_tk(ret)
      root = []
      curr = root
      while ret = parse_when(tslc)
        tslc = r_slc(ret)
        whn = r_tk(ret)
        _if = [
          "if",
          ["==", lcnd, whn[0]],
          whn[1]
        ]
        curr[3] = _if
        curr = _if
      end
      if root[3] != nil
        ret = parse_else(tslc)
        if ret
          tslc = r_slc(ret)
          bdy = r_tk(ret)
          curr[3] = bdy
        end
        ret = tk_expect(tslc, "kword")
        if ret && r_tk(ret)[1] == "end"
          tslc = r_slc(ret)
          [root[3], tslc]
        end
      end
    end
  end
end

def parse_while(tslc)
  ret = tk_expect(tslc, "kword")
  if ret && r_tk(ret)[1] == "while"
    tslc = r_slc(ret)
    ret = parse_assign_expr(tslc)
    if ret
      tslc = r_slc(ret)
      cnd = r_tk(ret)
      ret = parse_stmts(tslc)
      if ret
        tslc = r_slc(ret)
        bdy = r_tk(ret)
        ret = tk_expect(tslc, "kword")
        if ret && r_tk(ret)[1] == "end"
          tslc = r_slc(ret)
          [["while", cnd, bdy], tslc]
        end
      end
    end
  end
end

def parse_aexpr(tslc)
  ret = parse_term(tslc)
  if ret
    tslc = r_slc(ret)
    ltk = r_tk(ret)
    while (ret2 = tk_expect(tslc, "+") || tk_expect(tslc, "-"))
      tslc = r_slc(ret2)
      op = r_tk(ret2)
      ret = parse_term(tslc)
      if ret
        tslc = r_slc(ret)
        rtk = r_tk(ret)
        ltk = [op[0], ltk, rtk]
      end
    end
    [ltk, tslc]
  end
end

def parse_expr(tslc)
  ret = parse_aexpr(tslc)
  if ret
    tslc = r_slc(ret)
    ltk = r_tk(ret)
    while (ret2 = tk_expect(tslc, "<") || tk_expect(tslc, ">") || tk_expect(tslc, "<=") || tk_expect(tslc, ">=") || tk_expect(tslc, "==") || tk_expect(tslc, "!="))
      tslc = r_slc(ret2)
      op = r_tk(ret2)
      ret = parse_aexpr(tslc)
      if ret
        tslc = r_slc(ret)
        rtk = r_tk(ret)
        ltk = [op[0], ltk, rtk]
      end
    end
    [ltk, tslc]
  end
end

def parse_ary_ref_idx(tslc)
  ret = tk_expect(tslc, "[")
  if ret
    tslc = r_slc(ret)
    ret = parse_assign_expr(tslc)
    if ret
      tslc = r_slc(ret)
      idx = r_tk(ret)
      ret = tk_expect(tslc, "]")
      if ret
        tslc = r_slc(ret)
        [idx, tslc]
      end
    end
  end
end

def parse_bexpr(tslc)
  ret = parse_expr(tslc)
  if ret
    tslc = r_slc(ret)
    ltk = r_tk(ret)
    while (ret2 = tk_expect(tslc, "&&") || tk_expect(tslc, "||"))
      tslc = r_slc(ret2)
      op = r_tk(ret2)
      ret = parse_assign_expr(tslc)
      if ret
        tslc = r_slc(ret)
        rtk = r_tk(ret)
        ltk = [op[0], ltk, rtk]
      end
    end
    [ltk, tslc]
  end
end

def parse_assign_expr(tslc)
  ret = nil
  case true
  when bool(ret = parse_var_assign(tslc))
    ret
  when bool(ret = parse_ary_assign(tslc))
    ret
  when bool(ret = parse_bexpr(tslc))
    ret
  end
  ret
end

def parse_stmt(tslc)
  ret = nil
  case true
  when bool(ret = parse_assign_expr(tslc))
    ret
  when bool(ret = parse_func_def(tslc))
    ret
  end
  ret
end

def parse_stmts(tslc)
  stmts = ["stmts"]
  i = 1
  while (slen(tslc) > 0) && (ret = parse_stmt(tslc))
    stmts[i] = ret[0]
    tslc = ret[1]
    i = i + 1
  end
  [stmts, tslc]
end

def clean_comments(str)
  buf = ""
  i = 0
  is_comment = false
  is_str = false
  nl = "
"
  while str[i]
    if is_comment
      if str[i] == nl
        is_comment = false
      end
    else
      if "!" < str[i] && str[i] < "#"
        is_str = inv(is_str)
      end
      if is_str == false && str[i] == "#"
        is_comment = true
      else
        buf = buf + str[i]
      end
    end
    i = i + 1
  end
  buf
end

def parse(str)
  str = clean_comments(str)
  tslc = tokenize(fullslice(str))
  ret = parse_stmts(tslc)
  if slen(ret[1]) > 0
    p(ret[0])
    p(ret[1])
    raise("parse error")
  else
    ret[0]
  end
end

def fizzbuzz(n)
  if n % 3 == 0
    if n % 5 == 0
      "fizzbuzz"
    else
      "fizz"
    end
  else
    if n % 5 == 0
      "buzz"
    else
      n
    end
  end
end

# An implementation of the evaluator
def evaluate(exp, env, ftbl)
  # exp: A current node of AST
  # env: An environment (explained later)

  case exp[0]

#
## Problem 1: Arithmetics
#

  when "lit"
    exp[1] # return the immediate value as is

  when "+"
    evaluate(exp[1], env, ftbl) + evaluate(exp[2], env, ftbl)
  when "-"
    # Subtraction.  Please fill in.
    # Use the code above for addition as a reference.
    # (Almost just copy-and-paste.  This is an exercise.)
    evaluate(exp[1], env, ftbl) - evaluate(exp[2], env, ftbl)
  when "*"
    evaluate(exp[1], env, ftbl) * evaluate(exp[2], env, ftbl)
  when "/"
    evaluate(exp[1], env, ftbl) / evaluate(exp[2], env, ftbl)
  when "%"
    evaluate(exp[1], env, ftbl) % evaluate(exp[2], env, ftbl)
  when "<"
    evaluate(exp[1], env, ftbl) < evaluate(exp[2], env, ftbl)
  when "<="
    evaluate(exp[1], env, ftbl) <= evaluate(exp[2], env, ftbl)
  when ">"
    evaluate(exp[1], env, ftbl) > evaluate(exp[2], env, ftbl)
  when ">="
    evaluate(exp[1], env, ftbl) >= evaluate(exp[2], env, ftbl)
  when "=="
    evaluate(exp[1], env, ftbl) == evaluate(exp[2], env, ftbl)
  when "!="
    evaluate(exp[1], env, ftbl) != evaluate(exp[2], env, ftbl)
  when "&&"
    evaluate(exp[1], env, ftbl) && evaluate(exp[2], env, ftbl)
  when "||"
    evaluate(exp[1], env, ftbl) || evaluate(exp[2], env, ftbl)

  # ... Implement other operators that you need

  
#
## Problem 2: Statements and variables
#

  when "stmts"
    # Statements: sequential evaluation of one or more expressions.
    #
    # Advice 1: Insert `pp(exp)` and observe the AST first.
    # Advice 2: Apply `evaluate` to each child of this node.
    i = 1
    ret = nil
    while exp[i]
      ret = evaluate(exp[i], env, ftbl)
      i = i + 1
    end
    ret

  # The second argument of this method, `env`, is an "environement" that
  # keeps track of the values stored to variables.
  # It is a Hash object whose key is a variable name and whose value is a
  # value stored to the corresponded variable.

  when "var_ref"
    # Variable reference: lookup the value corresponded to the variable
    #
    # Advice: env[???]
    env[exp[1]]

  when "var_assign"
    # Variable assignment: store (or overwrite) the value to the environment
    #
    # Advice: env[???] = ???
    env[exp[1]] = evaluate(exp[2], env, ftbl)


#
## Problem 3: Branchs and loops
#

  when "if"
    # Branch.  It evaluates either exp[2] or exp[3] depending upon the
    # evaluation result of exp[1],
    #
    # Advice:
    #   if ???
    #     ???
    #   else
    #     ???
    #   end
    cond = evaluate(exp[1], env, ftbl)
    if cond
      evaluate(exp[2], env, ftbl)
    else
      exp[3] && evaluate(exp[3], env, ftbl)
    end

  when "while"
    # Loop.
    while evaluate(exp[1], env, ftbl)
      evaluate(exp[2], env, ftbl)
    end


#
## Problem 4: Function calls
#

  when "func_call"
    # Lookup the function definition by the given function name.
    func = ftbl[exp[1]]

    if func == nil
      # We couldn't find a user-defined function definition;
      # it should be a builtin function.
      # Dispatch upon the given function name, and do paticular tasks.
      case exp[1]
      when "p"
        # MinRuby's `p` method is implemented by Ruby's `p` method.
        p(evaluate(exp[2], env, ftbl))
      # ... Problem 4
      when "Integer"
        str = evaluate(exp[2], env, ftbl)
        Integer(str)
      when "fizzbuzz"
        fizzbuzz(evaluate(exp[2], env, ftbl))
      when "require"
        #require(evaluate(exp[2], env, ftbl))
      when "minruby_load"
        minruby_load()
      else
        raise("unknown builtin function")
      end
    else


#
## Problem 5: Function definition
#

      # (You may want to implement "func_def" first.)
      #
      # Here, we could find a user-defined function definition.
      # The variable `func` should be a value that was stored at "func_def":
      # parameter list and AST of function body.
      #
      # Function calls evaluates the AST of function body within a new scope.
      # You know, you cannot access a varible out of function.
      # Therefore, you need to create a new environment, and evaluate the
      # function body under the environment.
      #
      # Note, you can access formal parameters (*1) in function body.
      # So, the new environment must be initialized with each parameter.
      #
      # (*1) formal parameter: a variable as found in the function definition.
      # For example, `a`, `b`, and `c` are the formal parameters of
      # `def foo(a, b, c)`.
      env2 = {}
      func = ftbl[exp[1]]
      args = func[0]
      body = func[1]
      i = 0
      while args[i]
        env2[args[i]] = evaluate(exp[i + 2], env, ftbl)
        i = i + 1
      end
      evaluate(body, env2, ftbl)
    end

  when "func_def"
    # Function definition.
    #
    # Add a new function definition to function definition list.
    # The AST of "func_def" contains function name, parameter list, and the
    # child AST of function body.
    # All you need is store them into $function_definitions.
    #
    # Advice: $function_definitions[???] = ???
    ftbl[exp[1]] = [
      exp[2],
      exp[3]
    ]
    exp[2]


#
## Problem 6: Arrays and Hashes
#

  # You don't need advices anymore, do you?
  when "ary_new"
    i = 0
    ary = []
    while exp[i + 1]
      ary[i] = evaluate(exp[i + 1], env, ftbl)
      i = i + 1
    end
    ary

  when "ary_ref"
    evaluate(exp[1], env, ftbl)[evaluate(exp[2], env, ftbl)]

  when "ary_assign"
    evaluate(exp[1], env, ftbl)[evaluate(exp[2], env, ftbl)] = evaluate(exp[3], env, ftbl)

  when "hash_new"
    i = 1
    hash = {}
    while exp[i]
      hash[evaluate(exp[i], env, ftbl)] = evaluate(exp[i + 1], env, ftbl)
      i = i + 2
    end
    hash

  else
    p("error")
    p(exp)
    raise("unknown node")
  end
end


ftbl = {}
env = {}

# `minruby_load()` == `File.read(ARGV.shift)`
# `minruby_parse(str)` parses a program text given, and returns its AST
tree = parse(minruby_load())
#p("tree")
#p(tree)
#p("/tree")
evaluate(tree, env, ftbl)
