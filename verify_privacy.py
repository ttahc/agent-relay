from pathlib import Path
import logging,io,unittest
from pool.privacy import public,text,check_release,window_source,log_exception

class PrivacyTest(unittest.TestCase):
    def test_nested_secrets_and_invitation_fragment(self):
        secret='a'*40
        value={'token':secret,'items':[{'message':'Bearer '+secret,'url':'https://host/ai/join/i-id#key='+secret}]}
        rendered=str(public(value))
        self.assertNotIn(secret,rendered)
        self.assertIn('https://host/ai/join/i-id',rendered)
        self.assertEqual(value['token'],secret)
    def test_evidence_hashes_remain_useful(self):
        checksum='f'*64
        self.assertEqual(public({'sha256':checksum,'claim_id':'c-'+checksum,'version':3}),
                         {'sha256':checksum,'claim_id':'c-'+checksum,'version':3})
    def test_release_blocks_private_bytes_without_echo(self):
        secret=b'secret-value'
        try:check_release({'unsafe.key':b'-----BEGIN PRIVATE KEY-----\n'+secret})
        except ValueError as error:
            self.assertNotIn(secret.decode(),str(error));self.assertIn('unsafe.key',str(error))
        else:self.fail('private key accepted')
    def test_window_metadata_is_owner_scoped(self):
        state={'pilot':{'identity:peer':{'kind':'human','owner':'peer','status':'active'},
                         'identity:admin':{'kind':'human','owner':'admin','status':'active','admin':True}}}
        source={'executor_id':'window','owner':'owner','directory':'private','session':'private','device':'private','url':'private','window_name':'visible'}
        self.assertEqual(window_source(state,'owner',source),source)
        self.assertIsNone(window_source(state,'peer',source)['directory'])
        self.assertEqual(window_source(state,'peer',source)['window_name'],'visible')
    def test_logs_do_not_include_secret_or_traceback_locals(self):
        stream=io.StringIO();handler=logging.StreamHandler(stream);logging.getLogger().addHandler(handler)
        try:
            try:raise ValueError('Bearer '+'x'*40)
            except ValueError as error:incident=log_exception(error)
        finally:logging.getLogger().removeHandler(handler)
        self.assertNotIn('x'*40,stream.getvalue());self.assertIn(incident,stream.getvalue())
    def test_profile_path_masking_is_opt_in(self):
        raw='C:\\Users\\example\\work'
        self.assertEqual(text(raw),raw)
        self.assertIn('%USERPROFILE%',text(raw,True))

if __name__=='__main__':unittest.main()
