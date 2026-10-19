# ransomware-jpeg-recovery

Partial recovery of **JPEG photos encrypted by STOP/Djvu ransomware** (extensions such as `.dehd`, `.djvu`, `.qqqw`, ... with the `{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}` footer).

> This tool does **not** decrypt anything. It rebuilds the part of the photo that the ransomware left untouched.

## How it works

STOP/Djvu only encrypts the **first ~150 KB** of each file. In a JPEG that destroys the header (size, quantization and Huffman tables) and the top rows of the image, but the rest of the compressed data is intact.

Many phone cameras write **restart markers** (`FFD0`–`FFD7`) after every row of blocks. The script:

1. Finds the first restart marker after the encrypted region.
2. Decodes one interval with the standard JPEG Huffman tables to detect chroma subsampling and the number of blocks per row (→ image width).
3. Estimates the quantization tables automatically (block-edge smoothness + clipping), or copies the **exact** tables from an unencrypted photo of the same phone (`--ref`).
4. Writes a new JPEG header in front of the surviving data.

Large photos recover almost completely (a 3 MB photo ≈ 95 %); small ones only partially.

## Usage

```bash
pip install -r requirements.txt

# recover every file in a folder
python djvu_photo_recover.py "encrypted_folder" recovered

# exact colours: give one NOT-encrypted .JPG from the same phone
python djvu_photo_recover.py "encrypted_folder" recovered --ref original.JPG

# check which photos failed or look wrong (writes recovered/report.csv)
python check_recovered.py "encrypted_folder" recovered
```

Options: `--quality 90..99` forces a fixed quality instead of auto-calibration; `--width PIXELS` overrides the detected width if the result looks slanted.

## Limitations

- JPEG only (no PNG / HEIC / video).
- Needs restart markers and standard Huffman tables — typical for photos straight from many phones. Edited photos, WhatsApp/social-media copies and many DSLR photos will fail.
- The top part of the image (inside the encrypted 150 KB) cannot be recovered without the decryption key.

## If you are a victim

- Do not pay the ransom.
- Keep your encrypted files — keys for some variants have been published and Emsisoft's free STOP/Djvu decryptor may work later.
- Change your passwords from a clean device; this ransomware is often bundled with a password stealer.

---

## بالعربية

أداة لاسترجاع **الجزء السليم** من صور JPG التي شفّرها فيروس الفدية STOP/Djvu (مثل امتداد `.dehd`). الفيروس يشفّر أول 150 كيلوبايت فقط من كل ملف، والأداة تعيد بناء باقي الصورة.

```bash
pip install -r requirements.txt
python djvu_photo_recover.py "مجلد_الصور_المشفرة" recovered
python check_recovered.py "مجلد_الصور_المشفرة" recovered
```

لا تدفع الفدية، واحتفظ بالملفات المشفّرة، وغيّر كلمات المرور من جهاز آخر.

## License

MIT
