/*
 * Copyright (c) 2008-2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2008-2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "heim.h"
#include <string.h>


mit_krb5_error_code KRB5_CALLCONV
krb5_c_string_to_key(mit_krb5_context context,
		     mit_krb5_enctype enctype,
		     const mit_krb5_data *string,
		     const mit_krb5_data *salt,
		     mit_krb5_keyblock *key)
{
    krb5_data hstring;
    krb5_error_code ret;
    krb5_salt hsalt;
    krb5_keyblock hkey;
    
    LOG_ENTRY();

    mshim_mdata2hdata(string, &hstring);
    hsalt.salttype = KRB5_PADATA_PW_SALT;
    mshim_mdata2hdata(salt, &hsalt.saltvalue);

    ret = heim_krb5_string_to_key_data_salt(HC(context), enctype,
					    hstring, hsalt, &hkey);
    heim_krb5_data_free(&hstring);
    heim_krb5_data_free(&hsalt.saltvalue);
    if (ret)
	return ret;

    mshim_hkeyblock2mkeyblock(&hkey, key);
    heim_krb5_free_keyblock_contents(HC(context), &hkey);
    return 0;
}

mit_krb5_error_code KRB5_CALLCONV
krb5_principal2salt(mit_krb5_context context,
		    mit_krb5_const_principal principal,
		    mit_krb5_data *salt)
{
    struct comb_principal *c =  (struct comb_principal *)principal;
    krb5_error_code ret;
    krb5_salt hsalt;

    memset(salt, 0, sizeof(*salt));

    ret = heim_krb5_get_pw_salt(HC(context), c->heim, &hsalt);
    if (ret)
	return ret;
    mshim_hdata2mdata(&hsalt.saltvalue, salt);
    heim_krb5_free_salt(HC(context), hsalt);
    return 0;
}


mit_krb5_error_code  KRB5_CALLCONV
krb5_set_default_tgs_ktypes(mit_krb5_context, const mit_krb5_enctype *);


mit_krb5_error_code  KRB5_CALLCONV
krb5_set_default_tgs_ktypes(mit_krb5_context context,
			    const mit_krb5_enctype *enc)
{
    LOG_ENTRY();
    return heim_krb5_set_default_in_tkt_etypes(HC(context), (krb5_enctype *)enc);
}

mit_krb5_error_code KRB5_CALLCONV 
krb5_set_default_tgs_enctypes(mit_krb5_context context,
			      const mit_krb5_enctype *enc)
{
    LOG_ENTRY();
    return heim_krb5_set_default_in_tkt_etypes(HC(context), (krb5_enctype *)enc);
}


