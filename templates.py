crash_report_javascript = r"""
  function highlight(code) {
    var registers = "eax ax ah al ebx bx bh bl ecx cx ch cl edx dx dh dl "+
                    "esi si edi di ebp bp esp sp cs es ss fs ds gs eip";
    var x86insn   = "aaa aad aam aas adc add and call cbw clc cld cli cmc cmp "+
                    "cmpsb cmpsw cmpsd cwd daa das daa dec div esc hlt idiv imul "+
                    "in inc int into iret ja jae jb jbe jc jcxz je jg jge jl jle "+
                    "jna jnae jnb jnp jns jnz jo jp jpe jpo js jz jmp lahf lds "+
                    "lea les lock lodsb lodsw loop loope loopd loopne loopnz loopz "+
                    "loopw loopzw loopnew loopzd loopend loopzd mov movsb movsw "+
                    "movsx movzx movsd mul neg nop not or out pop popf popad popfd "+
                    "popa rcl rcr rep repe repne repnz repz ret retn retf rol ror "+
                    "sahf sal sar sbb scasb scasw shl shr stc std sti stosb stosw "+
                    "sub test wait xchg xlat xor enter ins leave outs bsf bsr bt "+
                    "btc btr bts cdq lfs lgs lss lodsd scasd seta shld shrd stosx "+
                    "xadd invd syscall sysret";

    var configs = {
      "#81BEF7": [new RegExp("\\b(" + registers.replace(/ /g, "|") + ")\\b", "g")],
      "#FE2E2E": [new RegExp("\\b(" + x86insn.replace(/ /g, "|") + ")\\b", "g")],
      "#F2F2F2": [/(0x([a-f0-9]+))/g],
      "#d7df01": [/(\[|\]|\+|\*|!)/g,
                  /\b(dword|db|word|byte)\b/g],
      "#666666": [/(,)/g]
    }

    for (var color in configs) {
      for (var item in configs[color]) {
        var replacement = "<font color='" + color + "'>$1</font>";
        code = code.replace(configs[color][item], replacement);
      }
    }
    return code;
  }

  function main() {
    var asm = document.getElementById("asmcode").innerHTML;
    var code = highlight(asm);
    document.getElementById("asmcode").innerHTML = code;
  }
  """

crash_report_html = r"""
  <html>
    <head>
      <script src="javascript.js"></script>
      <title>Crash Dump</title>
    </head>
    <body onload="main();" style="background-color:black; color:#4CC417;">
      <center>
        <table border="1" frame="border" rules="all" cellspacing="3" cellpadding="3">
          <tr>
            <td width="800" colspan="2" valign="top">
              <!--This part stores basic info-->
              <b><pre>{hook_info}</pre></b>
            </td>
          </tr>
          <tr>
            <td width="450" valign="top"><!-- Assembly -->
              <b><div id="asmcode"><pre>{assembly}</pre></div></b>
            </td>
            <td width="350" valign="top">
              <!-- Registers and SEH -->
              <font size="2" color="red"><b>Registers:</b></font>
              <pre>{registers}</pre>
                <font size="2" color="red"><b>SEH:</b></font>
              <pre>{seh}</pre>
              <font size="2" color="red"><b>Input Dump ({input_size} bytes):</b>
              <center>
                <pre>
                  <textarea rows="9" cols="38" style="border-width:1px;border-style:solid;border-color:lightgray;background-color:black;color:white;">{hexdata}</textarea>
                </pre>
              </center>
            </td>
          </tr>
          <tr>
            <td width="800" colspan="2" valign="top">
              <!-- WRITE/READ exception message, bug type (note), crash input -->
              <font size="2" color="red"><b>Exception:</b></font><font size="2">{violation}</font><br>
              <font size="2" color="red"><b>Note:</b></font><font size="2">{bug_type}</font><br>
            </td>
          </tr>
        </table>
      </center>
    </body>
  </html>
  """