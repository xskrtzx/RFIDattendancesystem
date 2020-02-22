#include <SPI.h>
#include <MFRC522.h>


#define RST_PIN    9   // 
#define SS_PIN    10    //

int SWITCH_PIN1 = A0; //
int SWITCH_PIN2 = A1; //
int val0,val1 = 0;

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance


MFRC522::MIFARE_Key key;
MFRC522::MIFARE_Key orikey;

String static Result;
byte checksum = 0;

byte *uid;
String suid;
String last_suid;

String inputString = "";         // a string to hold incoming data
boolean stringComplete = false;  // whether the string is complete

byte auth;
byte static b0[18];
String bwrite;//hidden saldo
String bwrite2;//hidden saldo
String bwrite3;//hidden saldo
String bread;//hidden saldo
int activeblock1;
int activeblock2;
int activeblock3;
int activesector;
String SWITCH_MODE;
String OLDSWITCH_MODE;
int SWITCH_STATE1;
int SWITCH_STATE2;


byte vreadmode = 1;
byte vwritemode = 0;
byte vreadmodeall=0;
//card dispenser Variable
 int i;
  int a;
String count;
  String cmd;
  int buttonpush=0;
String dev_id="2";  
void setup() {
  // put your setup code here, to run once:
  Serial.begin(57600);
  SPI.begin();      // Init SPI bus
  mfrc522.PCD_Init();
  mfrc522.PCD_AntennaOn();
  ShowReaderDetails();
  //delay(1000);
  //Serial.println("deviceid=" + dev_id);
  
   pinMode(SWITCH_PIN1, INPUT_PULLUP);
   pinMode(SWITCH_PIN2, INPUT_PULLUP);
   //digitalWrite(SWITCH_PIN1,LOW);
   //digitalWrite(SWITCH_PIN2,LOW);
    
}

void beep(int pin,int lenght,int x ) {
  int noteDuration = 1000 / lenght;
  for (int i=1;i<=x;i++) {
  
    tone(pin, 4978, noteDuration);
    int pauseBetweenNotes = noteDuration * 1.30;
    delay(pauseBetweenNotes);
    // stop the tone playing:
    noTone(pin);
  }
}
String uidstr(byte *buffer, byte bufferSize) {
  String suid;

  for (byte i = 0; i < bufferSize; i++) {
    suid += String(buffer[i], HEX);
    //printf(buffer[i] < 0x10 ? " 0" : " ");
    // Serial.print(buffer[i],HEX);

  }
  //Serial.print(suid);
  return suid;
}
void getkey(byte *buffer, byte bufferSize) {
  // for (byte i = 0; i < 6; i++) {
  //    key.keyByte[i] = 0xFF;
  //}
  for (byte i = 0; i <= 3; i++) {
    //  Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    //Serial.print(buffer[i]+i+1);
    if (buffer[i] == 255) {
      key.keyByte[i] = i + 1;
      if ((4 + i) < 6) {
        key.keyByte[4 + i] =  i + 1;
      }
    } else {
      key.keyByte[i] = buffer[i] + i + 1;
      if ((4 + i) < 6) {
        key.keyByte[4 + i] = buffer[i] + i + 1;
      }
    }


  }
  // return key;
}

byte Authenticate(byte trailerBlock)
{
  byte status;
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    // Serial.print(String(trailerBlock) +"PCD_Authenticate() failed: ");
    //Serial.println(mfrc522.GetStatusCodeName(status));
    return status;
  }
  // hasil=true;
  return status;
}
bool writevalue(byte blockAddr, String data)
{ bool hasil;
  byte status;
  byte blockdata[17];
 // Serial.println(data.length());
  if (data.length() > 16) return false;
  for (byte i = 0; i < 17; i++) {
    blockdata[i] = 32;
  }

  data.getBytes(blockdata, data.length()+1);
  blockdata[data.length()] = 32;

  /*Serial.println("");
  Serial.print(data);
  Serial.print("-");
  Serial.println(data.length());
  */

  status = mfrc522.MIFARE_Write(blockAddr, blockdata, 16);
  if (status != MFRC522::STATUS_OK) {
    // Serial.print(F("MIFARE_Write() failed: "));
    //Serial.println(mfrc522.GetStatusCodeName(status));
    hasil = false;
  } else {
    hasil = true;
  }
  return hasil;
}
bool chengekey(byte trailerBlock)
{
  byte status;
  byte buffer[18];
  byte size = sizeof(buffer);
  for (byte i = 0; i < 6; i++) {
    orikey.keyByte[i] = 0xFF;
  }
  byte trailerBuffer[] = {
    255, 255, 255, 255, 255, 255,       // Keep default key A
    0, 0, 0 ,
    0,
    255, 255, 255, 255, 255, 255
  };      // Keep default key B

  for (byte i = 0; i < 6; i++) {
    trailerBuffer[i] = key.keyByte[i];
    trailerBuffer[i + 10] = key.keyByte[i];
  }

  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &orikey, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
     //Serial.print(F("change key PCD_Authenticate() failed: "));
     //Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  mfrc522.MIFARE_SetAccessBits(&trailerBuffer[6], 0, 0, 0, 1);

 // Serial.println(F("Writing new sector trailer..."));
  status = mfrc522.MIFARE_Write(trailerBlock, trailerBuffer, 16);
  if (status != MFRC522::STATUS_OK) {
    //   Serial.print(F("change key MIFARE_Write() failed: "));
    // Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  //Serial.println("change key sukses");
  return true;
}
bool chengekeyori(byte trailerBlock)
{
  byte status;
  byte buffer[18];
  byte size = sizeof(buffer);
  for (byte i = 0; i < 6; i++) {
    orikey.keyByte[i] = 0xFF;
  }
  byte trailerBuffer[] = {
    255, 255, 255, 255, 255, 255,       // Keep default key A
    0, 0, 0 ,
    0,
    255, 255, 255, 255, 255, 255
  };      // Keep default key B

  for (byte i = 0; i < 6; i++) {
    trailerBuffer[i] = orikey.keyByte[i];
    trailerBuffer[i + 10] = orikey.keyByte[i];
  }

  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
     //Serial.print(F("change key PCD_Authenticate() failed: "));
     //Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  mfrc522.MIFARE_SetAccessBits(&trailerBuffer[6], 0, 0, 0, 1);

 // Serial.println(F("Writing new sector trailer..."));
  status = mfrc522.MIFARE_Write(trailerBlock, trailerBuffer, 16);
  if (status != MFRC522::STATUS_OK) {
    //   Serial.print(F("change key MIFARE_Write() failed: "));
    // Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  //Serial.println("change key sukses");
  return true;
}
String writemode() {
  //  Serial.print("writte mode");
  Result = "OK";
  //if (b4 == "") return "";
  if (activesector==0) {
    vwritemode=0;
     mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();
   
    return "";
  }

  uid = mfrc522.uid.uidByte;
  suid = uidstr(uid, mfrc522.uid.size);

  if (last_suid == suid) {

    getkey(uid, mfrc522.uid.size);

    last_suid = suid;
    
 
    if (activesector>0) {
      auth = Authenticate(activesector);
     activeblock1=activesector-3;
     activeblock2=activesector-2;
     activeblock3=activesector-1;
  }
    if (auth == MFRC522::STATUS_OK) {
      if (activesector==3){
         if (writevalue(activeblock2, bwrite2) == false) Result = "b2 gagal";
         if (writevalue(activeblock3, bwrite3) == false) Result = "b3 gagal";
      }else{
         if (writevalue(activeblock1, bwrite) == false) Result = "b1 gagal";
         if (writevalue(activeblock2, bwrite2) == false) Result = "b2 gagal";
         if (writevalue(activeblock3, bwrite3) == false) Result = "b3 gagal";
      }      
     // if (writevalue(2, b2) == false) Result = "b2 gagal";
    } else Result = "gagal2";

     activesector=0;
      bwrite="";  bwrite2=""; bwrite3="";
      vwritemode=0;
    // printArrayAscii(buffer,16);
    //last_suid="";
     Serial.println("write" + Result);
   // mfrc522.PICC_Select(NULL);

    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();
    //dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    // Halt PICC
    vreadmode=1;
  }
  return Result;
}
void resetcard() {
 // last_suid="";
  //mfrc522.PICC_Select(NULL);
 mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
 //Serial.println("reset");
    // Stop encryption on PCD
    
}
void readmode() {
  //updatekey();
  //mfrc522.PCD_StopCrypto1();
 //mfrc522.PICC_HaltA();
 //PICC_ReadCardSerial
  if ( mfrc522.PICC_IsNewCardPresent() ) {
    if (! mfrc522.PICC_ReadCardSerial() ) {
    suid = "";
    last_suid = "";
   // Serial.println("oldcard");
     // mfrc522.PICC_HaltA();
      return ;
           
    } else {
   //  Serial.println("new card");
    }
 } else {
   last_suid = "";
 
 return;
 }

  uid = mfrc522.uid.uidByte;
  suid = uidstr(uid, mfrc522.uid.size);

  if (last_suid == suid) {
      Serial.println("Ada Kartu");
    return;
  

  } else {

    // Serial.println("rq|" + id);
    getkey(uid, mfrc522.uid.size);

    last_suid = suid;
  if (chengekey(3)) {
     }
       
    //read_trailer(7);
    mfrc522.PCD_StopCrypto1();
    mfrc522.PICC_HaltA();
    if ( ! mfrc522.PICC_IsNewCardPresent() || ! mfrc522.PICC_ReadCardSerial() ) {

     Result="errorkey"; goto akhir;
    }
    
    auth = Authenticate(3);
    checksum = 0;
    Result = "";
    if (auth != MFRC522::STATUS_OK) {
      //Serial.println("Auth Fail");
      Result="auth"; goto akhir;
    }  else {
      //  Serial.println("Auth 3 OK");
      bread = read_block(1);
      // read_block(1,result);
     // Serial.println(b1 + " (Hidden Saldo)" );
      if (bread=="auth") {Result=bread; goto akhir;}
       
      Result +=  bread;
      checksum = 1; //1

       bread=read_block(2);  //Wd
      //Serial.println( b2+" (WD)");
     // Result += ";2" + b2;
       Result += ";" + bread;
      checksum +=1; //2
    }
    
  
//Serial.print(Result);
   

     Result+=";#"+String(checksum)+"#endread";
  
 akhir:   
   Serial.print(Result);
   
    vreadmode = 1;
    
    // printArrayAscii(buffer,16);
    // last_suid = "";
   // mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    //mfrc522.PCD_StopCrypto1();
    //dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    // Halt PICC

  }
}


String read_block(byte blockAddr  ) {
  //byte sector         = 1;
  //byte blockAddr      = 4;
  //byte trailerBlock   = 7;
  byte status;
  byte static  buffer[18] ;
  byte size = sizeof(buffer);
  //String val;


  status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    // Serial.print(F("MIFARE_Read() failed: "));
    //Serial.println(mfrc522.GetStatusCodeName(status));
    //  mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    // mfrc522.PCD_StopCrypto1();
    return "auth";
  }
  //return buffer;
  //val = GETSTRING(buffer, 16);
  // Serial.println(GETSTRING(buff,16));
  /*Serial.println("");
  Serial.print(val);
  Serial.println("-");
   for (byte i = 0; i < 16; i++) {
  Serial.print(buffer[i]);
  Serial.print(" ");
  }
  */


  return GETSTRING(buffer, 16);
}
String GETSTRING(byte array[], byte len)
{
  String val;
  for (byte i = 0; i < len;)
  {
    char c = array[i++];
    if (c < 0x20 || c > 0x7e)
    {
      val += String('.');
      //Serial.print('.');
    }
    else
    {
      val += String(char(c));
      // Serial.print(char(c));
    }
  }
  return val;
}
void ShowReaderDetails() {
  // Get the MFRC522 software version
  byte v = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
  Serial.print(F("MFRC522 Software Version: 0x"));
  Serial.print(v, HEX);
  if (v == 0x91)
    Serial.print(F(" = v1.0"));
  else if (v == 0x92)
    Serial.print(F(" = v2.0"));
  else
    Serial.print(F(" (unknown)"));
  Serial.println("");
  // When 0x00 or 0xFF is returned, communication probably failed
  if ((v == 0x00) || (v == 0xFF)) {
    Serial.println(F("WARNING: Communication failure, is the MFRC522 properly connected?"));
  }
}

void serialEvent() {
 
  while (Serial.available()) {
    // get the new byte:
    char inChar = (char)Serial.read();

    if (inChar == '\n') {
      stringComplete = true;
    } else {
      inputString += inChar;
    }
    if (stringComplete)
    {
       
   
      i = inputString.indexOf('#');
      cmd = inputString.substring(i + 1 , inputString.length());
       //     Serial.println(vwritemode);
     // Serial.println(cmd);
     // if (cmd.substring(0, 4) == "read"){
     //  Serial.println(cmd.substring(0, 5));
    //  Serial.println(cmd.substring(0, 4));
     // }
    
      // Serial.println(count);
      if (cmd.substring(0, 5) == "reset") {
       resetcard();
      
      vreadmode = 1;
        vwritemode = 0;  
      } else if (cmd.substring(0, 5) == "getid") {
       Serial.println("deviceid=" + dev_id);
      }else if (cmd.substring(0, 7) == "getmode") {
       Serial.println("mode=" + SWITCH_MODE);
      } 
      else if (cmd.substring(0, 3) == "wra") {
        //&& Ditengah == 1
        if (vwritemode == 0 ) {

          count = cmd.substring(3, cmd.length());
          activeblock1=0;
          activeblock2=0;
          activeblock3=0;
          activesector=0;
          
          if (count.toInt() > 0) {
            //Serial.println("alphnumeric");
            activesector=count.toInt();
              //Serial.println(idx);
              i = inputString.indexOf(';',0);
              bwrite = inputString.substring(0, i);
              a=i+1;
              i = inputString.indexOf(';', a);
              bwrite2 = inputString.substring(a, i);
              
              a=i+1;
              i = inputString.indexOf(';', a);
              bwrite3 = inputString.substring(a, i);
              
             vwritemode = 1;
             //Serial.println(bwrite);
            // Serial.println(bwrite2);
            // Serial.println(bwrite3);
            Serial.println("WRITEMODE");
           // Serial.flush();
          } //if count
        
        } // write mode

      } else if (cmd=="s3") {
        if (digitalRead(A3)==LOW) {
         Serial.println("ADA");        
        } else {
         Serial.println("KOSONG");
        }
       }else if (cmd=="s4") {
        if (digitalRead(A3)==HIGH) {
         Serial.println("ADA");        
        } else {
         Serial.println("KOSONG");
        }
       }else if (cmd == "read") {
        if (vreadmode == 0 ) {
           //Serial.println("READMODE");
           
             mfrc522.PICC_HaltA();
         // Stop encryption on PCD
         mfrc522.PCD_StopCrypto1();
          last_suid = "";
          vreadmode = 1;

        }

      }else if (cmd == "readall") {
        if (vreadmodeall == 0 ) {
           //Serial.println("READMODE");
           
             mfrc522.PICC_HaltA();
         // Stop encryption on PCD
         mfrc522.PCD_StopCrypto1();
          last_suid = "";
          vreadmodeall = 1;

        }

      } //switch


      inputString = "";
      stringComplete = false;
      Serial.flush();
    } // if string complete
  } // Serial Available
}// end function


void loop() {
  // put your main code here, to run repeatedly:
  if (vreadmode == 1) {
    readmode();
  } else if (vwritemode==1) {
   writemode();
  }else {

  
   //  Serial.println( digitalRead(EXIT_PIN));
  }
  val0 = digitalRead(SWITCH_PIN1);
  val1 = digitalRead(SWITCH_PIN2);
  Serial.print("MASUK : ");
  Serial.print(val0);
  Serial.print("  | Keluar : ");
  Serial.println(val1);
  delay(500);
  
  /*if (digitalRead(SWITCH_PIN1)==HIGH) {
    if (SWITCH_STATE1<10) {
     SWITCH_STATE1=SWITCH_STATE1+1;
    }
  } else {
    if (SWITCH_STATE1>-10) {
      SWITCH_STATE1=0;
    }
    
  }
  if (digitalRead(SWITCH_PIN2)==HIGH) {
    if (SWITCH_STATE2<10) {
     SWITCH_STATE2=SWITCH_STATE2+1;
    }
  } else {
    if (SWITCH_STATE2>-10) {
      SWITCH_STATE2=0;
    }
    
  }


  
  if (SWITCH_STATE1==10 && SWITCH_STATE2==0 ) {
  SWITCH_MODE="IN";
  } else if (SWITCH_STATE1==0 && SWITCH_STATE2==10 ) {
  SWITCH_MODE="OUT";  
  } else {
  SWITCH_MODE="OFF";  
  }
  
  if (OLDSWITCH_MODE!=SWITCH_MODE) {
  Serial.println("mode=" +SWITCH_MODE);
  OLDSWITCH_MODE=SWITCH_MODE;
  }
 //Serial.println(SWITCH_MODE);
*/

    if (val0==HIGH && val1==LOW) {
      SWITCH_MODE="OUT";
      Serial.println(SWITCH_MODE);
    } else if (val0==LOW && val1==HIGH) {
      SWITCH_MODE="IN";
      Serial.println(SWITCH_MODE);
    } else if (val0==HIGH && val1==HIGH) {
      SWITCH_MODE="OFF";
      Serial.println(SWITCH_MODE);
    }
    //Serial.print("KONDISI : ");
    //Serial.println(SWITCH_MODE);
}
