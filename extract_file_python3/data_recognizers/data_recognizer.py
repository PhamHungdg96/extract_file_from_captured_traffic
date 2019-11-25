import re

signatures={
    'avi':[(b'RIFF.{4}AVI LIST', None)],
    'bmp':[(b'\x42\x4D.{4}\x00\x00\x00\x00', None)],
    'elf':[(b'\x7F\x45\x4C\x46', None)],
    'exe':[(b'MZ.', None)],
    'gif':[(b'\x47\x49\x46\x38[\x37\x39]\x61', b'\x00\x3B')],
    'jpeg':[(b'\xFF\xD8\xFF', b'\xFF\xD9'), (b'.{6}\x4A\x46\x49\x46\x00', None)],
    'mkv':[(b'\x1A\x45\xDF\xA3.{4}matroska', None)],
    'mp3':[(b'ID3', None)],
    'mpg':[(b'\x00\x00\x01[\xB0-\xBF]', b'\x00\x00\x01[\xB7\xB9]')],
    'pdf':[(b'\x25\x50\x44\x46', b'.*\x25\x25\x45\x4F\x46[(\x0A)(\x0D)(\x0D\x0A)]?')],
    'png':[(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82')],
    'rar':[(b'\x52\x61\x72\x21\x1A\x07', None)],
    'wav':[(b'RIFF.{4}WAVEfmt', None)],
    'zip':[(b'\x50\x4B\x03\x04', None)]
}
class DataRecognizer(object):
    def init_signature(self,signature):
        regexstr = b''
        for (fileHeader, fileTrailer) in signature:   
            if fileTrailer is None:
                regexstr += b'(%s.*)|' % (fileHeader,)
            else:
                regexstr += b'(%s.*?%s)|' % (fileHeader, fileTrailer)
            print(regexstr[:-1])
        return re.compile(regexstr[:-1], re.DOTALL)
    def find_out(self, data):
        print(data[:100])
        for sig in signatures:
            _regex=self.init_signature(signatures[sig])
            print(_regex)
            match = _regex.match(data)
            print(match)
            if match:
                return sig,match.span()
        return None,None