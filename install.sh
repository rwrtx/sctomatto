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
BZh91AY&SY��Hn R�wP ����o߮���� �� `,���w�e����h��h�0�# ���OP� � ����M �=OP�@�����5M��@ @ F��
m1 hhh 2�F@   3Q&��O(i�4hh�A�F#M  4A��!1L&����&�HmFC �4� $���hS�iL�)�OOJ6�ѓ�@l��Fi�G���AI �>�,qƎ% ��B����H�;�84�Gϼ��]F���)�P��X�MmIfcf��rO|a�Hd�F"�;��]8ᅔ$v��<�PO�X`�*�8�������<2��P��s# Dpꓫ�F���Q�F����t��Y����Q����x��"�)����]��h     Ww7E���EA*�U�~n�[1�;�6���J(h���X�r�>�(��+US�}�� L'\ր�"6d2�!,d
(�Z V����S+�-�`j]�!�U �<0���!�$�w��j�4�K 	�٩����b��޶�����f���� ׁ3&̭����Ȉ�fߒ�Ż�R�x��3�U����0�b)j���zM�J��w��s( @�L�J)��']�)}�+�]���
�}T@*ݑ� �} w~���}:0��������C�� �J+X�I�̑�+����L�ֲG�A-���+f�� �\ūӴd��WU�m��m����(\�u���kA���P_;H���G��������5��R<wyKr�@�dkE�y��@��@�{�
H��T-L����}���!9��� �&�g��T``�J�]�*V���5c����.Z��;̻�0�	�p̰a����Ghn�Irm�DL��@�z�2JT���.ž|�����$_
Q �,�ί �6y����7�	�
�'x1ji/c� �j�{��W&j��"!.�y	8(�jm��,����n��K.@�y%Xc�P�r��k+�t�������vl\2�.��W�-��4�e�J�W�)ƴ8�����O���L��x�.��y���̯9 ��z���ڡ]X*�m�q������\�EN�������D�U�	�dI]�/����6@ t�3Wӏ+I��96�³S�֍�a�D"�1-�UJؔV��}r ��p���eA^�&�i��0��	j� ���&��^�r�M�OMZ�,� pE2��@+0�&�9͔��2�l�[���wp��>S2�lW䩠W��˩P�=a`���c'PI$�d*(<�礨�`�տ+���z��[)��X�FIHt��ٗG-Er���hZ�$b����B�o�ŊcH��J�d���M��l_��;N��6��+y�5k٫=Fq���L���eշ\w<����_11-�ӳ��e��sa��JD1�J��2��b��dA$j�C���P��Vh�Ԧ�=���U�� ��Z���m��7;��c���5�.l��� ��u�}mJ�:�۴��a���UɎ�h��ݝ]6#��6+fH��R4W׾@]SG_�h�*Ԝ��:ʬֵl�O����$�!�B�x��)���Cp