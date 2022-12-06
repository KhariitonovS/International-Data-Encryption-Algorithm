using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Course
{
    public partial class MainForm : Form
    {
        private IDEAManaged alg;
        private Thread thread;
        ManualResetEvent suspend = new ManualResetEvent(true);

        private string letLow = "qwertyuiopasdfghjklzxcvbnm";
        private string letUp = "QWERTYUIOPASDFGHJKLZXCVBNM";
        private string digits = "1234567890";
        private string symbols = "!@#$%";

        private string pool = "";
        private string curKey = "";
        private uint counter = 1;
        
        public MainForm()
        {
            InitializeComponent();
            alg = new IDEAManaged();
            alg.Mode = CipherMode.ECB;
            alg.Padding = PaddingMode.ANSIX923;
            alg.GenerateIV();
            button4.Enabled = false;
            button5.Enabled = false;
        }

        private void foo(int n, OpenFileDialog o)
        {
            if (n > 0)
            {
                foreach (char item in pool)
                {
                    curKey += item;
                    foo(n - 1, o);
                    try
                    {
                        using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
                        {
                            byte[] k1 = Encoding.ASCII.GetBytes(curKey);
                            md5.TransformFinalBlock(k1, 0, k1.Length);
                            alg.Key = md5.Hash;
                        }
                        IDEAManagedCryptor tr = (IDEAManagedCryptor)alg.CreateDecryptor();
                        using (FileStream iStr = new FileStream(o.FileName, FileMode.Open, FileAccess.Read))
                        using (MemoryStream mstr = new MemoryStream())
                        {
                            using (CryptoStream cStr = new CryptoStream(iStr, tr, CryptoStreamMode.Read))
                            {
                                cStr.CopyTo(mstr);
                            }
                            byte[] b = mstr.ToArray();
                            try
                            {
                                b = tr.RemovePadding(b);
                            }
                            catch (CryptographicException)
                            {
                                curKey = curKey.Remove((int)numericUpDownLen.Value - n);
                                continue;
                            }

                            ListViewItem LV_item = new ListViewItem(curKey);
                            LV_item.SubItems.Add(new string(Encoding.Default.GetChars(b, 0, b.Length)));
                            listView.Items.Add(LV_item);
                            curKey = curKey.Remove((int)numericUpDownLen.Value - n);

                            suspend.WaitOne(Timeout.Infinite); // По сигналу остановить поток
                            counter++;

                            if (counter == (int)numericUpDownStep.Value)
                            {
                                suspend.Reset();
                                counter = 1;
                            }
                            
                        }
                    }
                    catch (IndexOutOfRangeException)
                    {
                        MessageBox.Show(this, "Invalid file for decryption!\nChoose another file", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                }
            }

            if (n == (int)numericUpDownLen.Value)
            {
                labelProgress.Text = "Completed!";
            }

        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            AboutBox1 AB1 = new AboutBox1();
            AB1.labelProductName.Text = "Криптографические методы защиты информации.";
            AB1.labelVersion.Text = "Версия 2.0";
            AB1.labelCopyright.Text = "Авторские права: Харитонов С.Н.";
            AB1.labelCompanyName.Text = "Название организации: НИУ МЭИ.  Группа: А-13-18";
            AB1.textBoxDescription.Text = "Тема курсовой работы: Программная реализация криптоалгоритма IDEA.\r\n\r\n" +
                                            "Тема расчетного задания: Разработка программы криптоанализа шифра IDEA.";
            AB1.ShowDialog();
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked) Key.PasswordChar = '\0';
            else Key.PasswordChar = '*';
        }

        private void Edit_Click(object sender, EventArgs e)
        {
            PasswordEdit p = new PasswordEdit((string)Key.Text.Clone());
            if (p.ShowDialog(this) == DialogResult.OK) Key.Text = p.PasswordResult;
        }

        private void button6_Click(object sender, EventArgs e)
        {
            OpenFileDialog win = new OpenFileDialog();
            win.CheckFileExists = true;
            win.CheckPathExists = true;
            win.Multiselect = false;
            win.SupportMultiDottedExtensions = true;
            win.Title = "Select file to encrypt";
            if (win.ShowDialog(this) == DialogResult.OK)
                if (textBox3.Text != win.FileName) textBox4.Text = win.FileName;
                else MessageBox.Show(this, "Input and output file are the same file.", "Wrong file", MessageBoxButtons.OK);
            if (File.Exists(textBox4.Text))
            {
                try
                {
                    button4.Enabled = button5.Enabled = Directory.Exists(new FileInfo(textBox3.Text).DirectoryName);
                }
                catch (Exception)
                {
                    button4.Enabled = button5.Enabled = false;
                }
            }
            else button4.Enabled = button5.Enabled = false;
        }

        private void button7_Click(object sender, EventArgs e)
        {
            SaveFileDialog s = new SaveFileDialog();
            s.CheckPathExists = true;
            s.SupportMultiDottedExtensions = true;
            s.Title = "Select file to save encryption";
            if (s.ShowDialog(this) == DialogResult.OK)
                if (textBox4.Text != s.FileName) textBox3.Text = s.FileName;
                else MessageBox.Show(this, "Input and output file are the same file.", "Wrong file", MessageBoxButtons.OK);
            if (File.Exists(textBox4.Text))
            {
                try
                {
                    button4.Enabled = button5.Enabled = Directory.Exists(new FileInfo(textBox3.Text).DirectoryName);
                }
                catch (Exception)
                {
                    button4.Enabled = button5.Enabled = false;
                }
            }
            else button4.Enabled = button5.Enabled = false;
        }

        private void button9_Click(object sender, EventArgs e)
        {
            OpenFileDialog win = new OpenFileDialog();
            win.CheckFileExists = true;
            win.CheckPathExists = true;
            win.Multiselect = false;
            win.SupportMultiDottedExtensions = true;
            win.Title = "Select file to load";
            if (win.ShowDialog(this) != DialogResult.OK) return;
            using (StreamReader sr = new StreamReader(win.FileName, Encoding.Default))
            {
                string[] s = new string[0];
                while (!sr.EndOfStream)
                {
                    Array.Resize(ref s, s.Length + 1);
                    s[s.Length - 1] = sr.ReadLine();
                }
                textBox2.Lines = s;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            SaveFileDialog s = new SaveFileDialog();
            s.CheckPathExists = true;
            s.SupportMultiDottedExtensions = true;
            s.Title = "Select file to save text";
            if (s.ShowDialog(this) != DialogResult.OK) return;
            using (StreamWriter sw = new StreamWriter(s.FileName, false, Encoding.Default))
            {
                for (int i = 0; i < textBox2.Lines.Length; i++)
                {
                    sw.WriteLine(textBox2.Lines[i]);
                }
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (!radioButton1.Checked)
                MessageBox.Show("Change operating mode.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
            {
                string ifname = textBox4.Text, ofname = textBox3.Text;
                if (!File.Exists(ifname))
                {
                    MessageBox.Show(this, "File Not Found", "Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                if (ofname == "")
                {
                    MessageBox.Show(this, "Invalid File Name", "Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
                {
                    byte[] k1 = Encoding.ASCII.GetBytes(Key.Text);
                    md5.TransformFinalBlock(k1, 0, k1.Length);
                    alg.Key = md5.Hash;
                }
                IDEAManagedCryptor tr = (IDEAManagedCryptor)alg.CreateEncryptor();
                using (BinaryReader br = new BinaryReader(new FileStream(ifname, FileMode.Open, FileAccess.Read)))
                using (FileStream oStr = new FileStream(ofname, FileMode.Create, FileAccess.Write))
                using (CryptoStream cStr = new CryptoStream(oStr, tr, CryptoStreamMode.Write))
                using (BinaryWriter bw = new BinaryWriter(cStr))
                {
                    byte[] b = br.ReadBytes((int)br.BaseStream.Length);
                    b = tr.AddPadding(b);
                    bw.Write(b);
                }

                DialogResult res = MessageBox.Show("Delete the original file?", "Action", MessageBoxButtons.YesNo, MessageBoxIcon.Information);

                if (res == DialogResult.Yes)
                {
                    FileInfo fi1 = new FileInfo(textBox4.Text);
                    fi1.Delete();
                    button4.Enabled = false;
                    button5.Enabled = false;
                    textBox4.Text = "";
                }
                MessageBox.Show(this, "Cryptographic operation completed successfully!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            if (!radioButton2.Checked)
                MessageBox.Show("Change operating mode.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
            {
                string ifname = textBox4.Text, ofname = textBox3.Text;
                if (!File.Exists(ifname))
                {
                    MessageBox.Show(this, "File Not Found", "Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                if (ofname == "")
                {
                    MessageBox.Show(this, "Invalid File Name", "Error", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                try
                {
                    using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
                    {
                        byte[] k1 = Encoding.ASCII.GetBytes(Key.Text);
                        md5.TransformFinalBlock(k1, 0, k1.Length);
                        alg.Key = md5.Hash;
                    }
                    IDEAManagedCryptor tr = (IDEAManagedCryptor)alg.CreateDecryptor();
                    using (FileStream iStr = new FileStream(ifname, FileMode.Open, FileAccess.Read))
                    using (FileStream oStr = new FileStream(ofname, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cStr = new CryptoStream(iStr, tr, CryptoStreamMode.Read))
                    using (MemoryStream mstr = new MemoryStream())
                    using (BinaryWriter bw = new BinaryWriter(oStr))
                    {
                        cStr.CopyTo(mstr);
                        byte[] b = mstr.ToArray();
                        try
                        {
                            b = tr.RemovePadding(b);
                        }
                        catch (CryptographicException)
                        {
                            MessageBox.Show(this, "Unable to decrypt file. Password is wrong!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                        bw.Write(b);
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    MessageBox.Show(this, "Invalid file for decryption!\nChoose another file", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                DialogResult res = MessageBox.Show("Delete the original file?", "Action", MessageBoxButtons.YesNo, MessageBoxIcon.Information);

                if (res == DialogResult.Yes)
                {
                    FileInfo fi1 = new FileInfo(textBox4.Text);
                    fi1.Delete();
                    button4.Enabled = false;
                    button5.Enabled = false;
                    textBox4.Text = "";
                }
                MessageBox.Show(this, "Cryptographic operation completed successfully!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            Key.ReadOnly = true;
            Edit.Enabled = true;
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            Key.ReadOnly = false;
            Edit.Enabled = false;
            Key.Text = "";
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (!radioButton2.Checked)
                MessageBox.Show("Change operating mode.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
            {
                OpenFileDialog o = new OpenFileDialog();
                o.CheckFileExists = true;
                o.CheckPathExists = true;
                o.Multiselect = false;
                o.SupportMultiDottedExtensions = true;
                o.Title = "Select file to load";
                if (o.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
                    {
                        byte[] k1 = Encoding.ASCII.GetBytes(Key.Text);
                        md5.TransformFinalBlock(k1, 0, k1.Length);
                        alg.Key = md5.Hash;
                    }
                    IDEAManagedCryptor tr = (IDEAManagedCryptor)alg.CreateDecryptor();
                    using (FileStream iStr = new FileStream(o.FileName, FileMode.Open, FileAccess.Read))
                    using (MemoryStream mstr = new MemoryStream())
                    {
                        using (CryptoStream cStr = new CryptoStream(iStr, tr, CryptoStreamMode.Read))
                        {
                            cStr.CopyTo(mstr);
                        }
                        byte[] b = mstr.ToArray();
                        try
                        {
                            b = tr.RemovePadding(b);
                        }
                        catch (CryptographicException)
                        {
                            MessageBox.Show(this, "Unable to decrypt file. Password is wrong!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                        textBox2.Text = new string(Encoding.Default.GetChars(b, 0, b.Length));
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    MessageBox.Show(this, "Invalid file for decryption!\nChoose another file", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (!radioButton1.Checked)
                MessageBox.Show("Change operating mode.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
            {
                SaveFileDialog s = new SaveFileDialog();
                s.CheckPathExists = true;
                s.SupportMultiDottedExtensions = true;
                s.Title = "Select file to save text";
                if (s.ShowDialog(this) != DialogResult.OK) return;
                using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
                {
                    byte[] k1 = Encoding.ASCII.GetBytes(Key.Text);
                    md5.TransformFinalBlock(k1, 0, k1.Length);
                    alg.Key = md5.Hash;
                }
                IDEAManagedCryptor tr = (IDEAManagedCryptor)alg.CreateEncryptor();
                using (FileStream oStr = new FileStream(s.FileName, FileMode.Create, FileAccess.Write))
                using (CryptoStream cStr = new CryptoStream(oStr, tr, CryptoStreamMode.Write))
                using (BinaryWriter bw = new BinaryWriter(cStr))
                {
                    byte[] b = Encoding.Default.GetBytes(textBox2.Text);
                    b = tr.AddPadding(b);
                    bw.Write(b);
                }
            }
        }

        private void button8_Click(object sender, EventArgs e)
        {
            suspend.Set();
            pool = "";
            listView.Items.Clear();

            if (numericUpDownLen.Value == 0)
            {
                MessageBox.Show("Estimated key length cannot be 0.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (!(checkBoxLow.Checked | checkBoxUp.Checked | checkBoxDig.Checked | checkBoxSym.Checked))
                {
                    MessageBox.Show("Select character sets to use.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    if (checkBoxLow.Checked)
                    {
                        pool += letLow;
                    }
                    if (checkBoxUp.Checked)
                    {
                        pool += letUp;
                    }
                    if(checkBoxDig.Checked)
                    {
                        pool += digits;
                    }
                    if(checkBoxSym.Checked)
                    {
                        pool += symbols;
                    }

                    if (!radioButton2.Checked)
                        MessageBox.Show("Change operating mode.", "Action", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    else
                    {
                        OpenFileDialog o = new OpenFileDialog();
                        o.CheckFileExists = true;
                        o.CheckPathExists = true;
                        o.Multiselect = false;
                        o.SupportMultiDottedExtensions = true;
                        o.Title = "Select file to load";
                        if (o.ShowDialog(this) != DialogResult.OK) return;

                        try { 
                            CheckForIllegalCrossThreadCalls = false;
                            thread = new Thread(() =>
                            {
                                foo((int)numericUpDownLen.Value, o);

                            })
                            {
                                IsBackground = false,
                                Priority = ThreadPriority.AboveNormal
                            };                        
                            thread.Start();

                            labelProgress.Text = "In progress...";

                            button8.Enabled = false;
                            button10.Enabled = true;
                            button11.Enabled = true;
                            button12.Enabled = true;
                        }
                        catch (Exception)
                        {

                        }

                    }
                }
            }
       
        }

        private void button10_Click(object sender, EventArgs e)
        {
            suspend.Reset();
        }

        private void button11_Click(object sender, EventArgs e)
        {
            suspend.Set();
        }

        private void button12_Click(object sender, EventArgs e)
        {
            thread.Abort();

            numericUpDownLen.Value = 0;
            numericUpDownStep.Value = 100;
            checkBoxLow.Checked = false;
            checkBoxUp.Checked = false;
            checkBoxDig.Checked = false;
            checkBoxSym.Checked = false;

            labelProgress.Text = "";

            listView.Items.Clear();

            pool = "";
            curKey = "";

            button8.Enabled = true;
            button10.Enabled = false;
            button11.Enabled = false;
            button12.Enabled = false;

        }
    }
}
