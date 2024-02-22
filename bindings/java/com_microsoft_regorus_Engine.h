/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_microsoft_regorus_Engine */

#ifndef _Included_com_microsoft_regorus_Engine
#define _Included_com_microsoft_regorus_Engine
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    newEngine
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_microsoft_regorus_Engine_newEngine
  (JNIEnv *, jclass);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    addPolicy
 * Signature: (JLjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_addPolicy
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    addPolicyFromFile
 * Signature: (JLjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_addPolicyFromFile
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    addDataJson
 * Signature: (JLjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_addDataJson
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    addDataJsonFromFile
 * Signature: (JLjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_addDataJsonFromFile
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    setInputJson
 * Signature: (JLjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_setInputJson
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    setInputJsonFromFile
 * Signature: (JLjava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_setInputJsonFromFile
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    evalQuery
 * Signature: (JLjava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_microsoft_regorus_Engine_evalQuery
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     com_microsoft_regorus_Engine
 * Method:    destroyEngine
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_microsoft_regorus_Engine_destroyEngine
  (JNIEnv *, jclass, jlong);

#ifdef __cplusplus
}
#endif
#endif