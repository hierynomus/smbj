package com.hierynomus.msfscc.fileinformation;

public class FileLinkInformation
	extends FileRenameInformation
{
	public FileLinkInformation( final  boolean replaceIfExists, final String fileName ) 
	{
		super(replaceIfExists, 0L, fileName);
	}
}
