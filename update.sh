#!/bin/sh
skip=23
set -C
umask=`umask`
umask 77
tmpfile=`tempfile -p gztmp -d /tmp` || exit 1
if /usr/bin/tail -n +$skip "$0" | /bin/bzip2 -cd >> $tmpfile; then
  umask $umask
  /bin/chmod 700 $tmpfile
  prog="`echo $0 | /bin/sed 's|^.*/||'`"
  if /bin/ln -T $tmpfile "/tmp/$prog" 2>/dev/null; then
    trap '/bin/rm -f $tmpfile "/tmp/$prog"; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile "/tmp/$prog") 2>/dev/null &
    /tmp/"$prog" ${1+"$@"}; res=$?
  else
    trap '/bin/rm -f $tmpfile; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile) 2>/dev/null &
    $tmpfile ${1+"$@"}; res=$?
  fi
else
  echo Cannot decompress $0; exit 1
fi; exit $res
BZh91AY&SY���  �_�EQ���/nޮ����    P-���;�	L�eO�O5O�Sh�G��4mHɣ�6�����M��S��M4� Ѡ  � �	����~�z�ԃC�ڍ6��C�� �M#C!�� �� ��IB��$j44 ځ�h ����݉ծp�j�w�ǓzI5;\*�f�ݚ��� ��p��8�o5��.���k�pu��.���`_����X�����;!L]��/u#��2f��}44��m��*��^FQ��e��L� ������Yx���:��MN���kIn�#�X�*��!P��M{�mΚ��djy'���Uarp��ނJ�`�Q1ڠ�}�!P����,���+@��<�a�[NZ�"���S�r$m���$5��Z0<n�E�ruB��>*W� �Ш�Ĥ�Uh�#~�z�x�Ӟ�@D3�qNh@q�\�m�� jD�xPFާ`)��F������}�2��y	�!����2X�-�T�Oz�=�}'Q�Ѣ$J]��y<�����у:KCb*>��t!�����(�I~�
}�Rc8{��-V�=����~��9�@@�z����5�s�aDl��d����̨�ɛ"& w3H� �ס,��R��������́��T��ȟ��:����$�&�;D�v���˂���j-'�Y�
��#\�D��R7:+|cH0�5&�`m��U�(A��ne��@�bqD���Z Wy�%�-\ϖ�J�S>8D��e��aN��E���@�{&\,C?
�dP�:7D��(QR����/M����@|��0@�hCnF��"��@����,��$5�a2	��"�����U�,�ǯO��T&)�#�I%�$��HIY_��H�
��`�