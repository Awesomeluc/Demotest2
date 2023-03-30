/* Decompiler 16ms, total 476ms, lines 68 */
package burp;

import evilwan.Geronimo;
import evilwan.Goewie;
import evilwan.WSGui;
import evilwan.WSPacket;
import java.awt.Component;

public class BurpExtender implements IBurpExtender, ITab {
   private static final String TAB_CAPTION = "WS Stuff";
   private static final String EXT_NAME = "WebSockets Stuff v1.7.15";
   private IBurpExtenderCallbacks _cb = null;
   private Component _tabpane = null;

   private static void say(String s) {
      System.out.println("BurpExtender -- " + s);
   }

   public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
      this._cb = cb;
      this._cb.setExtensionName("WebSockets Stuff v1.7.15");
      this._tabpane = new WSGui();
      this._cb.addSuiteTab(this);
      String[] args = this._cb.getCommandLineArguments();
      int i = 0;

      while(i < args.length) {
         if (args[i].equals("-strings")) {
            try {
               ++i;
               String var10000 = args[i];
               ++i;
               Geronimo.dumpClassesFromFile(var10000, args[i], ".dump");
            } catch (Throwable var5) {
               say("caught: " + var5);
               var5.printStackTrace();
            }
         } else if (args[i].equals("-dumpgui")) {
            try {
               Goewie.dumpBurpComponents();
            } catch (Throwable var7) {
               say("caught: " + var7);
               var7.printStackTrace();
            }
         } else if (args[i].equals("-analyze")) {
            try {
               this._tabpane = new Goewie();
               this._cb.addSuiteTab(this);
            } catch (Throwable var6) {
               say("caught: " + var6);
               var6.printStackTrace();
            }
         } else if (args[i].equals("-XXX")) {
            WSPacket.setDebug(true);
         }
      }

   }

   public String getTabCaption() {
      return "WS Stuff";
   }

   public Component getUiComponent() {
      return this._tabpane;
   }
}
