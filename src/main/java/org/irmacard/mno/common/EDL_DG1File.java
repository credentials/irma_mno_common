package org.irmacard.mno.common;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVOutputStream;

import org.jmrtd.io.SplittableInputStream;



/**
 * Created by fabianbr on 25-1-16.
 * File structure for the eDL_DG1 file.
 * Datagroup 1 contains TODO
 *
 *
 * copied most code from org.jmrtd.lds.DG1File, but adapted it to the eDL setting
 */
public class EDL_DG1File {
    private static final short DEMOGRAPHIC_INFO_TAG = 0x5F1F;

    //private static final short CATEGORIES_INFO_TAG = 0x7F63;

    private DriverDemographicInfo driverInfo;

    private int dataGroupTag = 0x61;
    private int dataGroupLength;

    //TODO
    //private List<CategoryInfo> categories = new ArrayList<CategoryInfo>();

    /**
     * Constructs a new file.
     *
     * @param driverInfo
     *            the driver info object
     * //@param categories
     *            the list of driving categories
     */
    public EDL_DG1File(DriverDemographicInfo driverInfo
                   /*List<CategoryInfo> categories*/) {
        this.driverInfo = driverInfo;
        //this.categories.addAll(categories);
    }

    /**
     * Constructs a new file based on the data in <code>in</code>.
     *
     * @param in
     *            the input stream with the data to be decoded
     * @throws IOException
     *             if decoding fails
     */
 /*   public EDL_DG1File(InputStream in) throws IOException {
        BERTLVInputStream tlvIn = new BERTLVInputStream(in);

        isSourceConsistent = false;

        tlvIn.readLength();
        byte[] valueBytes = tlvIn.readValue();
        BERTLVObject mainObject = new BERTLVObject(tag, valueBytes);
        BERTLVObject demographicObject = mainObject
                .getSubObject(DEMOGRAPHIC_INFO_TAG);
        BERTLVObject categoryObject = mainObject
                .getSubObject(CATEGORIES_INFO_TAG);

        this.driverInfo = new DriverDemographicInfo(new ByteArrayInputStream(
                (byte[]) demographicObject.getValue()));
        BERTLVObject numObject = categoryObject
                .getSubObject(BERTLVObject.INTEGER_TYPE_TAG);
        int totalCat = ((byte[]) numObject.getValue())[0];

        for (int i = 0; i < totalCat; i++) {
            BERTLVObject catObject = categoryObject.getChildByIndex(i + 1);
            categories.add(new CategoryInfo(new ByteArrayInputStream(
                    (byte[]) catObject.getEncoded())));
        }
    }*/
        /**
         * Creates a new file based on an input stream.
         *
         * @param in an input stream
         *
         * @throws IOException if something goes wrong
         */
        public EDL_DG1File(InputStream in) throws IOException {
            this.dataGroupTag = dataGroupTag;
            readObject(in);
        }


    /**
     * Reads the contents of this data group, including tag and length from an input stream.
     *
     * @param inputStream the stream to read from
     *
     * @throws IOException if reading from the stream fails
     */
    protected void readObject(InputStream inputStream) throws IOException {
        TLVInputStream tlvIn = inputStream instanceof TLVInputStream ? (TLVInputStream)inputStream : new TLVInputStream(inputStream);
        int tag = tlvIn.readTag();
        if (tag != dataGroupTag) {
            throw new IllegalArgumentException("Was expecting tag " + Integer.toHexString(dataGroupTag) + ", found " + Integer.toHexString(tag));
        }
        dataGroupLength = tlvIn.readLength();
        inputStream = new SplittableInputStream(inputStream, dataGroupLength);
        readContent(inputStream);
    }

    protected void readContent(InputStream in) throws IOException {
        TLVInputStream tlvIn = in instanceof TLVInputStream ? (TLVInputStream)in : new TLVInputStream(in);
        tlvIn.skipToTag(DEMOGRAPHIC_INFO_TAG);
        int length = tlvIn.readLength();
        byte[] contents = tlvIn.readValue();
        this.driverInfo = new DriverDemographicInfo(new ByteArrayInputStream (contents));
            //this.driverInfo = new DriverDemographicInfo(tlvIn);
    }



    /**
     * Gets the Driver information stored in this file.
     *
     * @return the Driver information
     */
    public DriverDemographicInfo getDriverInfo() {
        return driverInfo;
    }

    public String toString() {
        return "DG1File: " + driverInfo.toString() + "\n";
    }





}
