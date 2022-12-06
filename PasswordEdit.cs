using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Course
{
    public partial class PasswordEdit : Form
    {
        public PasswordEdit(string str)
        {
            InitializeComponent();
            rests = new List<PassRestriction>();
            rests.Add(new PassRestriction("qwertyuiopasdfghjklzxcvbnm", (int)numericUpDown1.Value));
            rests.Add(new PassRestriction("QWERTYUIOPASDFGHJKLZXCVBNM", (int)numericUpDown2.Value));
            rests.Add(new PassRestriction("1234567890", (int)numericUpDown3.Value));
            rests.Add(new PassRestriction("!@#$%^&*", (int)numericUpDown4.Value));
            rests.Add(new PassRestriction(",.?/;:|\\~", (int)numericUpDown5.Value));
            rests.Add(new PassRestriction("()[]{}<>'\"", (int)numericUpDown6.Value));
            textBox1.Text = str;
        }

        public string PasswordResult { get { return textBox1.Text; } }

        private List<PassRestriction> rests;
        private class PassRestriction
        {
            public PassRestriction(string chars, int min)
            {
                MinCount = min;
                Set = chars.ToCharArray();
            }
            public char[] Set;
            public int MinCount;
            public bool Obseres(string password)
            {
                return password.Count(p => Set.Contains(p)) >= MinCount;
            }
        }
        private void UpdCB()
        {
            if (minmin() > (int)numericUpDown8.Value) numericUpDown8.Value = (decimal)minmin();
            if (minmin() > (int)numericUpDown7.Value) numericUpDown7.Value = (decimal)minmin();
            checkBox1.Checked = rests[0].Obseres(textBox1.Text);
            checkBox2.Checked = rests[1].Obseres(textBox1.Text);
            checkBox3.Checked = rests[2].Obseres(textBox1.Text);
            checkBox4.Checked = rests[3].Obseres(textBox1.Text);
            checkBox5.Checked = rests[4].Obseres(textBox1.Text);
            checkBox6.Checked = rests[5].Obseres(textBox1.Text);
            checkBox7.Checked = textBox1.Text.Length >= (int)numericUpDown7.Value;
            checkBox8.Checked = textBox1.Text.Length <= (int)numericUpDown8.Value;
        }
        private int minmin()
        {
            return (int)(numericUpDown1.Value + numericUpDown2.Value + numericUpDown3.Value +
                numericUpDown4.Value + numericUpDown5.Value + numericUpDown6.Value);
        }

        private void numericUpDown1_ValueChanged(object sender, EventArgs e)
        {
            rests[0].MinCount = (int)numericUpDown1.Value;
            UpdCB();
        }

        private void numericUpDown2_ValueChanged(object sender, EventArgs e)
        {
            rests[1].MinCount = (int)numericUpDown2.Value;
            UpdCB();
        }

        private void numericUpDown3_ValueChanged(object sender, EventArgs e)
        {
            rests[2].MinCount = (int)numericUpDown3.Value;
            UpdCB();
        }

        private void numericUpDown4_ValueChanged(object sender, EventArgs e)
        {
            rests[3].MinCount = (int)numericUpDown4.Value;
            UpdCB();
        }

        private void numericUpDown5_ValueChanged(object sender, EventArgs e)
        {
            rests[4].MinCount = (int)numericUpDown5.Value;
            UpdCB();
        }

        private void numericUpDown6_ValueChanged(object sender, EventArgs e)
        {
            rests[5].MinCount = (int)numericUpDown6.Value;
            UpdCB();
        }

        private void numericUpDown7_ValueChanged(object sender, EventArgs e)
        {
            if (numericUpDown7.Value > numericUpDown8.Value)
                numericUpDown7.Value = numericUpDown8.Value;
            UpdCB();
        }

        private void numericUpDown8_ValueChanged(object sender, EventArgs e)
        {
            if (numericUpDown8.Value < numericUpDown7.Value)
                numericUpDown8.Value = numericUpDown7.Value;
            UpdCB();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            UpdCB();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }
        private void button2_Click(object sender, EventArgs e)
        {
            if (checkBox1.Checked && checkBox2.Checked && checkBox3.Checked && checkBox4.Checked &&
                checkBox5.Checked && checkBox6.Checked && checkBox7.Checked && checkBox8.Checked)
            {
                if (textBox1.Text == textBox2.Text)
                {
                    DialogResult = DialogResult.OK;
                    Close();
                }
                else
                    MessageBox.Show("Password mismatch.", "Action", MessageBoxButtons.RetryCancel, MessageBoxIcon.Information);
            }
            else
                MessageBox.Show(this, "Not all restrictions are met.");
        }
    }
}
