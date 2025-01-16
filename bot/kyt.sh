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
BZh91AY&SY��� ���{�����o߯����       `�����'�޷���@�j��P�AI&���M5�=G��H`�#Mi�����h��2)�h�Q$�@        hd�L�  M &� � 	L�h�&�	����j �4=M ���b����Sz��OCS�P���4   �"�	�?)�L�d���44�4�4J���L�UN��̼�c��ɛ�C��u�չ�"=���}h�z6Cψ�I�W4��]h�F9¤(gP!�(�J�l[yX;�E��)m(F sJ����*G�Yl��3]�׫�懢���d���k���< ��g>���
!f�Mdt�N lޮ��p}��RQ��t��!tr�i�϶������m��m��UbC�Q�.��	ظ[G��>���9m��[�]qqُJ;S';���u]F5�6�\��8:�b��	%�;�P�����eN�S�����%�#R�%pߤA�.��_\�H%�����^f9M���]��V�f�hH� �ɉ����)��@�0-W��d��NP��e[m�9��O�sm�'_"� �#&��bġ*�bY���]԰���R�(�<�+#]X8 �}94����m� �ⱟ�Db�J��� ��>Y����`�|�`M����������l��x�rV��m��T7&�oF�{�ۃ��/ �"b��ž~x���9
o9�&�2Q��`F���1"*K�9q�ō�d�Ҩ�Sw˛{�^��o�����3�9�����*b�����?���΍Y��C�C�4��z����g�9���q*�J�܍^L"��<*�5y��+;;��$�$��J�&!�&4ƻ���]f�걁������n	d�V�V�#�|m�ۚ�y3��(V|�JB"W�ca��mԱ���%Ȥ9�n�*�ők�� ��)::7Rz�\��y*�]iA�vy3��/+d�#�I�G 9����W�kp���&��j����W�Q{�2���pi�*�Y����0Ie��-Tb�H*W5P��b;��9�6��B�-��H�fm0���;�z�*$�os;H,����V����H4g=�~P��1e�~'mrɤ����8�q��XxP���\7�\��|�Wd��2��2�Ҝ�ŨV�j	#1�8I~�j8+�q���]�(s?2-����1�&�܋аp����g3��?1U�I�����i...1%]��t1���_C���RC6�D��SF�N�p3"�����m���A>/�l,� �$��C�ʎt-6�z�b��m<��D0l@�4�"��З�\݊(��j�_���"D�U��z�U�lzH�,�\=A*�c��5���:�S��'6n��iY D���ɛSf H9���^!��Z8�v�#P:�orX���S"X�������u]�er��H��²���"���R
±%H���F��iE�HoV�����: J��Z�s��J�(��L��h 
$�H�Daf�);^�dʜ�[9;��@��Q�!e�l�Ӭe�L.I5�����ay�\=g��� y�H�
�.�ܤi-.@N[]�2��V���6ԮW�B� jE\���C0)�bVٯ�YߩZ����Fuu�$��b�O6Vzv�2\��-)̏n#��՟b��t���dm���T9@������!��]��BB^xC�